/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <string.h>
#include <errno.h>
#include <time.h>

#include <petnet.h>

#include <petlib/pet_util.h>
#include <petlib/pet_log.h>
#include <petlib/pet_hashtable.h>
#include <petlib/pet_json.h>

#include <util/ip_address.h>
#include <util/inet.h>
#include <util/checksum.h>

#include "ethernet.h"
#include "ipv4.h"
#include "tcp.h"
#include "tcp_connection.h"
#include "packet.h"
#include "socket.h"
#include "timer.h"

extern int petnet_errno;

struct tcp_state {
	struct tcp_con_map * con_map;
};

#define TCP_RTO_SECS 1

#define TCP_MSS      1460u

#define TCP_INIT_SSTHRESH (64u * TCP_MSS)

static uint16_t __calculate_tcp_checksum(struct packet    * pkt,
										  struct ipv4_addr * src_ip,
										  struct ipv4_addr * dst_ip);

static void __retx_timeout_cb(struct pet_timeout * timeout, void * arg);

static inline struct tcp_raw_hdr *
__get_tcp_hdr(struct packet * pkt)
{
	struct tcp_raw_hdr * tcp_hdr = pkt->layer_2_hdr + pkt->layer_2_hdr_len
								   + pkt->layer_3_hdr_len;

	pkt->layer_4_type    = TCP_PKT;
	pkt->layer_4_hdr     = tcp_hdr;
	pkt->layer_4_hdr_len = tcp_hdr->header_len * 4;

	return tcp_hdr;
}

static inline struct tcp_raw_hdr *
__make_tcp_hdr(struct packet * pkt,
			   uint32_t        option_len)
{
	pkt->layer_4_type    = TCP_PKT;
	pkt->layer_4_hdr     = pet_malloc(sizeof(struct tcp_raw_hdr) + option_len);
	pkt->layer_4_hdr_len = sizeof(struct tcp_raw_hdr) + option_len;

	return (struct tcp_raw_hdr *)(pkt->layer_4_hdr);
}

static inline void *
__get_payload(struct packet * pkt)
{
	if (pkt->layer_3_type == IPV4_PKT) {
		struct ipv4_raw_hdr * ipv4_hdr = pkt->layer_3_hdr;

		pkt->payload     = pkt->layer_4_hdr + pkt->layer_4_hdr_len;
		pkt->payload_len = ntohs(ipv4_hdr->total_len)
						   - (pkt->layer_3_hdr_len + pkt->layer_4_hdr_len);

		return pkt->payload;
	} else {
		log_error("Unhandled layer 3 packet format\n");
		return NULL;
	}
}

static inline void
__init_pkt(struct packet * pkt)
{
	pkt->layer_2_hdr_len = 0;
	pkt->layer_3_hdr_len = 0;
	pkt->layer_4_hdr_len = 0;
	pkt->payload_len     = 0;
	pkt->layer_2_hdr     = NULL;
	pkt->layer_3_hdr     = NULL;
	pkt->layer_4_hdr     = NULL;
	pkt->payload         = NULL;
}

static void
__save_pending(struct tcp_connection * con,
			   struct packet         * pkt,
			   uint32_t               seq_num)
{
	uint32_t total = pkt->layer_4_hdr_len + pkt->payload_len;

	if (con->pending_pkt) {
		pet_free(con->pending_pkt);
	}

	con->pending_pkt     = pet_malloc(total);
	con->pending_pkt_len = total;
	con->pending_seq_num = seq_num;

	memcpy(con->pending_pkt, pkt->layer_4_hdr, pkt->layer_4_hdr_len);

	if (pkt->payload_len > 0 && pkt->payload) {
		memcpy(con->pending_pkt + pkt->layer_4_hdr_len,
			   pkt->payload,
			   pkt->payload_len);
	}
}

static void
__clear_pending(struct tcp_connection * con)
{
	if (con->retx_timeout) {
		pet_cancel_timeout(con->retx_timeout);
		con->retx_timeout = NULL;
	}

	if (con->pending_pkt) {
		pet_free(con->pending_pkt);
		con->pending_pkt = NULL;
	}

	con->pending_pkt_len       = 0;
	con->pending_seq_num       = 0;
	con->pending_pkt_sent_time = 0;
	con->dup_ack_cnt           = 0;
}

static int
__retransmit_pending(struct tcp_connection * con)
{
	uint32_t hdr_len     = sizeof(struct tcp_raw_hdr);
	uint32_t payload_len = con->pending_pkt_len - hdr_len;

	struct packet      * pkt = create_empty_packet();
	struct tcp_raw_hdr * hdr = NULL;

	if (!pkt) return -1;

	__init_pkt(pkt);

	pkt->layer_3_type    = IPV4_PKT;
	pkt->layer_3_hdr_len = ipv4_expected_hdr_len();
	pkt->layer_4_type    = TCP_PKT;
	pkt->layer_4_hdr     = pet_malloc(hdr_len);
	pkt->layer_4_hdr_len = hdr_len;

	memcpy(pkt->layer_4_hdr, con->pending_pkt, hdr_len);

	hdr = (struct tcp_raw_hdr *)pkt->layer_4_hdr;
	hdr->ack_num  = htonl(con->expected_seq_num); 
	hdr->checksum = 0;

	if (payload_len > 0) {
		pkt->payload     = pet_malloc(payload_len);
		pkt->payload_len = payload_len;
		memcpy(pkt->payload, con->pending_pkt + hdr_len, payload_len);
	}

	hdr->checksum = __calculate_tcp_checksum(pkt,
											  con->ipv4_tuple.local_ip,
											  con->ipv4_tuple.remote_ip);

	pet_printf("__retransmit_pending: retransmitting seq=%u\n",
			   con->pending_seq_num);

	if (ipv4_pkt_tx(pkt, con->ipv4_tuple.remote_ip) == -1) {
		log_error("__retransmit_pending: ipv4_pkt_tx failed\n");
		
		pet_free(pkt->layer_4_hdr);
		pkt->layer_4_hdr = NULL;
		if (pkt->payload) {
			pet_free(pkt->payload);
			pkt->payload = NULL;
		}
		free_packet(pkt);
		return -1;
	}

	
	get_tcp_con(con);
	con->retx_timeout = pet_add_timeout(TCP_RTO_SECS, __retx_timeout_cb,
										 (void *)con);
	return 0;
}

static void
__retx_timeout_cb(struct pet_timeout * timeout, void * arg)
{
	struct tcp_connection * con = (struct tcp_connection *)arg;

	lock_tcp_con(con);

	
	con->retx_timeout = NULL;

	if (con->pending_pkt == NULL) {
		
		unlock_tcp_con(con);
		put_tcp_con(con);
		return;
	}

	pet_printf("__retx_timeout_cb: RTO fired for seq=%u\n",
			   con->pending_seq_num);

	
	con->ssthresh = (con->cwnd / 2 > TCP_MSS) ? con->cwnd / 2 : TCP_MSS;
	con->cwnd     = TCP_MSS;
	con->dup_ack_cnt = 0;

	__retransmit_pending(con); 

	unlock_tcp_con(con);
	put_tcp_con(con); 
}

static int
__send_tcp_pkt(struct tcp_connection * con,
			   uint32_t                seq,
			   uint32_t                ack,
			   uint8_t                 syn,
			   uint8_t                 ack_flag,
			   uint8_t                 fin,
			   void                  * data,
			   uint32_t                data_len,
			   int                     save_for_retx)
{
	struct packet      * pkt = create_empty_packet();
	struct tcp_raw_hdr * hdr = NULL;

	if (!pkt) return -1;

	__init_pkt(pkt);

	pkt->layer_3_type    = IPV4_PKT;
	pkt->layer_3_hdr_len = ipv4_expected_hdr_len();

	hdr = __make_tcp_hdr(pkt, 0);

	hdr->src_port   = htons(con->ipv4_tuple.local_port);
	hdr->dst_port   = htons(con->ipv4_tuple.remote_port);
	hdr->seq_num    = htonl(seq);
	hdr->ack_num    = htonl(ack);
	hdr->header_len = 5; 
	hdr->flags.SYN  = syn;
	hdr->flags.ACK  = ack_flag;
	hdr->flags.FIN  = fin;
	//CHANGE BY UTAKRSH AFTER SUBMITTING
	//BEFORE: 1 LINE 269
	//hdr->recv_win   = htons((uint16_t)pet_socket_recv_capacity(con->sock));
	//AFTER: 2 LINES
	uint16_t win = (uint16_t)pet_socket_recv_capacity(con->sock);
	hdr->recv_win = htons(win > 0 ? win : 65535);

	hdr->checksum   = 0;
	hdr->urgent_ptr = 0;

	if (data && data_len > 0) {
		pkt->payload     = pet_malloc(data_len);
		pkt->payload_len = data_len;
		memcpy(pkt->payload, data, data_len);
	}

	hdr->checksum = __calculate_tcp_checksum(pkt,
											  con->ipv4_tuple.local_ip,
											  con->ipv4_tuple.remote_ip);

	if (save_for_retx) {
		
		__save_pending(con, pkt, seq);
	}

	if (ipv4_pkt_tx(pkt, con->ipv4_tuple.remote_ip) == -1) {
		log_error("__send_tcp_pkt: ipv4_pkt_tx failed\n");
		
		pet_free(pkt->layer_4_hdr);
		pkt->layer_4_hdr = NULL;
		if (pkt->payload) {
			pet_free(pkt->payload);
			pkt->payload = NULL;
		}
		free_packet(pkt);
		if (save_for_retx) {
			
			pet_free(con->pending_pkt);
			con->pending_pkt     = NULL;
			con->pending_pkt_len = 0;
			con->pending_seq_num = 0;
		}
		return -1;
	}

	if (save_for_retx) {
		
		get_tcp_con(con);
		con->retx_timeout = pet_add_timeout(TCP_RTO_SECS, __retx_timeout_cb,
											 (void *)con);
	}

	return 0;
}

static int
__send_ack(struct tcp_connection * con)
{
	return __send_tcp_pkt(con,
						  con->next_seq_num,
						  con->expected_seq_num,
						  0, 1, 0,
						  NULL, 0,
						  0);
}

pet_json_obj_t
tcp_hdr_to_json(struct tcp_raw_hdr * hdr)
{
	pet_json_obj_t hdr_json = PET_JSON_INVALID_OBJ;

	hdr_json = pet_json_new_obj("TCP Header");

	if (hdr_json == PET_JSON_INVALID_OBJ) {
		log_error("Could not create TCP Header JSON\n");
		goto err;
	}

	pet_json_add_u16 (hdr_json, "src port",   ntohs(hdr->src_port));
	pet_json_add_u16 (hdr_json, "dst port",   ntohs(hdr->dst_port));
	pet_json_add_u32 (hdr_json, "seq num",    ntohl(hdr->seq_num));
	pet_json_add_u32 (hdr_json, "ack num",    ntohl(hdr->ack_num));
	pet_json_add_u8  (hdr_json, "header len", hdr->header_len * 4);
	pet_json_add_bool(hdr_json, "URG flag",   hdr->flags.URG);
	pet_json_add_bool(hdr_json, "ACK flag",   hdr->flags.ACK);
	pet_json_add_bool(hdr_json, "PSH flag",   hdr->flags.PSH);
	pet_json_add_bool(hdr_json, "RST flag",   hdr->flags.RST);
	pet_json_add_bool(hdr_json, "SYN flag",   hdr->flags.SYN);
	pet_json_add_bool(hdr_json, "FIN flag",   hdr->flags.FIN);
	pet_json_add_u16 (hdr_json, "recv win",   ntohs(hdr->recv_win));
	pet_json_add_u16 (hdr_json, "checksum",   ntohs(hdr->checksum));
	pet_json_add_u16 (hdr_json, "urgent ptr", ntohs(hdr->urgent_ptr));

	return hdr_json;

err:
	if (hdr_json != PET_JSON_INVALID_OBJ) pet_json_free(hdr_json);
	return PET_JSON_INVALID_OBJ;
}

void
print_tcp_header(struct tcp_raw_hdr * tcp_hdr)
{
	pet_json_obj_t hdr_json = PET_JSON_INVALID_OBJ;
	char         * json_str = NULL;

	hdr_json = tcp_hdr_to_json(tcp_hdr);

	if (hdr_json == PET_JSON_INVALID_OBJ) {
		log_error("Could not serialize TCP Header to JSON\n");
		return;
	}

	json_str = pet_json_serialize(hdr_json);
	pet_printf("\"TCP Header\": %s\n", json_str);
	pet_free(json_str);
	pet_json_free(hdr_json);
}

int
tcp_listen(struct socket    * sock,
		   struct ipv4_addr * local_addr,
		   uint16_t           local_port)
{
	pet_printf("tcp_listen called on port %d\n", local_port);

	struct tcp_state * tcp_state = petnet_state->tcp_state;

	struct ipv4_addr wildcard;
	memset(&wildcard, 0, sizeof(struct ipv4_addr));

	struct tcp_connection * con = create_ipv4_tcp_con(tcp_state->con_map,
													   &wildcard,
													   &wildcard,
													   local_port,
													   0);
	if (con == NULL) return -1;

	con->con_state = LISTEN;

	if (add_sock_to_tcp_con(tcp_state->con_map, con, sock) != 0) {
		log_error("tcp_listen: failed to add socket\n");
		remove_tcp_con(tcp_state->con_map, con);
		put_and_unlock_tcp_con(con);
		return -1;
	}

	put_and_unlock_tcp_con(con);
	return 0;
}

int
tcp_connect_ipv4(struct socket    * sock,
				 struct ipv4_addr * local_addr,
				 uint16_t           local_port,
				 struct ipv4_addr * remote_addr,
				 uint16_t           remote_port)
{
	struct tcp_state      * tcp_state = petnet_state->tcp_state;
	struct tcp_connection * con       = NULL;

	con = create_ipv4_tcp_con(tcp_state->con_map,
							   local_addr,
							   remote_addr,
							   local_port,
							   remote_port);
	if (con == NULL) {
		log_error("tcp_connect_ipv4: failed to create connection\n");
		return -1;
	}

	con->next_seq_num     = 0;
	con->expected_seq_num = 0;
	con->con_state        = SYN_SENT;
	con->remote_recv_win  = TCP_MSS;   
	con->cwnd             = TCP_MSS;   
	con->ssthresh         = TCP_INIT_SSTHRESH;
	con->dup_ack_cnt      = 0;

	if (add_sock_to_tcp_con(tcp_state->con_map, con, sock) != 0) {
		log_error("tcp_connect_ipv4: failed to add socket\n");
		remove_tcp_con(tcp_state->con_map, con);
		put_and_unlock_tcp_con(con);
		return -1;
	}

	
	if (__send_tcp_pkt(con,
					   con->next_seq_num,
					   0,
					   1, 0, 0,
					   NULL, 0,
					   1) == -1) {
		log_error("tcp_connect_ipv4: failed to send SYN\n");
		remove_tcp_con(tcp_state->con_map, con);
		put_and_unlock_tcp_con(con);
		return -1;
	}

	con->next_seq_num += 1; 

	put_and_unlock_tcp_con(con);
	return 0;
}

int
tcp_send(struct socket * sock)
{
	struct tcp_state      * tcp_state = petnet_state->tcp_state;
	struct tcp_connection * con       = get_and_lock_tcp_con_from_sock(
											tcp_state->con_map, sock);

	if (con == NULL) {
		log_error("tcp_send: no connection for socket\n");
		return -1;
	}

	if (con->con_state != ESTABLISHED) {
		log_error("tcp_send: connection not ESTABLISHED (state=%d)\n",
				  con->con_state);
		put_and_unlock_tcp_con(con);
		return -1;
	}

	
	if (con->pending_pkt != NULL) {
		pet_printf("tcp_send: segment in flight, deferring\n");
		put_and_unlock_tcp_con(con);
		return 0;
	}

	uint32_t data_len = pet_socket_send_capacity(sock);
	if (data_len == 0) {
		put_and_unlock_tcp_con(con);
		return 0;
	}

	
	uint32_t limit = con->cwnd < con->remote_recv_win
					 ? con->cwnd : con->remote_recv_win;
	if (limit == 0) {
		
		pet_printf("tcp_send: zero window, deferring\n");
		put_and_unlock_tcp_con(con);
		return 0;
	}
	if (data_len > limit)   data_len = limit;
	if (data_len > TCP_MSS) data_len = TCP_MSS;

	uint8_t * data = pet_malloc(data_len);
	pet_socket_sending_data(sock, data, data_len);

	int ret = __send_tcp_pkt(con,
							  con->next_seq_num,
							  con->expected_seq_num,
							  0, 1, 0,
							  data, data_len,
							  1);
	pet_free(data);

	if (ret == -1) {
		log_error("tcp_send: __send_tcp_pkt failed\n");
		put_and_unlock_tcp_con(con);
		return -1;
	}

	con->next_seq_num += data_len;

	put_and_unlock_tcp_con(con);
	return 0;
}

int
tcp_close(struct socket * sock)
{
	struct tcp_state      * tcp_state = petnet_state->tcp_state;
	struct tcp_connection * con       = get_and_lock_tcp_con_from_sock(
											tcp_state->con_map, sock);

	if (con == NULL) {
		return 0; 
	}

	if (con->con_state == ESTABLISHED) {
		pet_printf("tcp_close: ESTABLISHED -> FIN_WAIT1\n");

		if (__send_tcp_pkt(con,
						   con->next_seq_num,
						   con->expected_seq_num,
						   0, 1, 1,
						   NULL, 0,
						   1) == -1) {
			log_error("tcp_close: failed to send FIN\n");
			put_and_unlock_tcp_con(con);
			return -1;
		}

		con->next_seq_num += 1;
		con->con_state     = FIN_WAIT1;

	} else if (con->con_state == CLOSE_WAIT) {
		pet_printf("tcp_close: CLOSE_WAIT -> LAST_ACK\n");

		if (__send_tcp_pkt(con,
						   con->next_seq_num,
						   con->expected_seq_num,
						   0, 1, 1,
						   NULL, 0,
						   1) == -1) {
			log_error("tcp_close: failed to send FIN\n");
			put_and_unlock_tcp_con(con);
			return -1;
		}

		con->next_seq_num += 1;
		con->con_state     = LAST_ACK;

	} else {
		pet_printf("tcp_close: state=%d, nothing to do\n", con->con_state);
	}

	put_and_unlock_tcp_con(con);
	return 0;
}

static uint16_t
__calculate_tcp_checksum(struct packet    * pkt,
						 struct ipv4_addr * src_ip,
						 struct ipv4_addr * dst_ip)
{
	struct ipv4_pseudo_hdr pseudo_hdr;
	uint16_t checksum = 0;

	memset(&pseudo_hdr, 0, sizeof(struct ipv4_pseudo_hdr));

	ipv4_addr_to_octets(src_ip, pseudo_hdr.src_ip);
	ipv4_addr_to_octets(dst_ip, pseudo_hdr.dst_ip);
	pseudo_hdr.rsvd   = 0;
	pseudo_hdr.proto  = IPV4_PROTO_TCP;
	pseudo_hdr.length = htons(pkt->layer_4_hdr_len + pkt->payload_len);

	checksum = calculate_checksum_begin(
				   &pseudo_hdr, sizeof(struct ipv4_pseudo_hdr) / 2);
	checksum = calculate_checksum_continue(
				   checksum, pkt->layer_4_hdr, pkt->layer_4_hdr_len / 2);

	if (pkt->payload_len > 0) {
		checksum = calculate_checksum_finalize(
					   checksum, pkt->payload, pkt->payload_len / 2);
	} else {
		checksum = calculate_checksum_finalize(checksum, NULL, 0);
	}

	return checksum;
}

int
tcp_pkt_rx(struct packet * pkt)
{
	if (pkt->layer_3_type != IPV4_PKT) return -1;

	struct tcp_raw_hdr  * tcp_hdr  = __get_tcp_hdr(pkt);
	struct ipv4_raw_hdr * ipv4_hdr = pkt->layer_3_hdr;

	struct ipv4_addr * local_ip  = ipv4_addr_from_octets(ipv4_hdr->dst_ip);
	struct ipv4_addr * remote_ip = ipv4_addr_from_octets(ipv4_hdr->src_ip);

	
	struct tcp_connection * con = get_and_lock_tcp_con_from_ipv4(
		petnet_state->tcp_state->con_map,
		local_ip,
		remote_ip,
		ntohs(tcp_hdr->dst_port),
		ntohs(tcp_hdr->src_port)
	);

	free_ipv4_addr(local_ip);
	free_ipv4_addr(remote_ip);

	
	if (!con) {
		struct ipv4_addr wildcard;
		memset(&wildcard, 0, sizeof(struct ipv4_addr));

		con = get_and_lock_tcp_con_from_ipv4(
			petnet_state->tcp_state->con_map,
			&wildcard,
			&wildcard,
			ntohs(tcp_hdr->dst_port),
			0
		);
	}

	if (!con) {
		pet_printf("tcp_pkt_rx: no connection found, dropping\n");
		return 0;
	}

	if (petnet_state->debug_enable) {
		pet_printf("tcp_pkt_rx: state=%d\n", con->con_state);
		print_tcp_header(tcp_hdr);
	}

	
	if (con->con_state == LISTEN && tcp_hdr->flags.SYN && !tcp_hdr->flags.ACK) {

		pet_printf("tcp_pkt_rx: LISTEN got SYN\n");

		struct socket    * serv_sock = con->sock;
		struct ipv4_addr * l_ip      = ipv4_addr_from_octets(ipv4_hdr->dst_ip);
		struct ipv4_addr * r_ip      = ipv4_addr_from_octets(ipv4_hdr->src_ip);

		struct tcp_connection * new_con = create_ipv4_tcp_con(
			petnet_state->tcp_state->con_map,
			l_ip, r_ip,
			ntohs(tcp_hdr->dst_port),
			ntohs(tcp_hdr->src_port)
		);

		free_ipv4_addr(l_ip);
		free_ipv4_addr(r_ip);

		if (!new_con) {
			put_and_unlock_tcp_con(con);
			return -1;
		}

		new_con->expected_seq_num = ntohl(tcp_hdr->seq_num) + 1;
		new_con->next_seq_num     = 100;
		new_con->con_state        = SYN_RCVD;
		new_con->sock             = serv_sock;
		
		new_con->remote_recv_win  = ntohs(tcp_hdr->recv_win);
		new_con->cwnd             = TCP_MSS;
		new_con->ssthresh         = TCP_INIT_SSTHRESH;
		new_con->dup_ack_cnt      = 0;

		int ret = __send_tcp_pkt(new_con,
								  new_con->next_seq_num,
								  new_con->expected_seq_num,
								  1, 1, 0,
								  NULL, 0,
								  1);

		new_con->next_seq_num += 1;

		if (ret == -1) {
			log_error("tcp_pkt_rx: failed to send SYN-ACK\n");
			remove_tcp_con(petnet_state->tcp_state->con_map, new_con);
			put_and_unlock_tcp_con(new_con);
			put_and_unlock_tcp_con(con);
			return -1;
		}

		put_and_unlock_tcp_con(new_con);
		put_and_unlock_tcp_con(con);
		return 0;
	}

	
	if (con->con_state == SYN_RCVD && tcp_hdr->flags.SYN && !tcp_hdr->flags.ACK) {

		pet_printf("tcp_pkt_rx: SYN_RCVD got SYN retry\n");

		__send_tcp_pkt(con,
					   con->next_seq_num - 1,
					   con->expected_seq_num,
					   1, 1, 0,
					   NULL, 0,
					   0);

		put_and_unlock_tcp_con(con);
		return 0;
	}

	
	if (con->con_state == SYN_RCVD && tcp_hdr->flags.ACK) {

		pet_printf("tcp_pkt_rx: SYN_RCVD got ACK -> ESTABLISHED\n");

		__clear_pending(con); 

		con->con_state = ESTABLISHED;

		struct socket * new_sock = pet_socket_accepted(con->sock,
														con->ipv4_tuple.remote_ip,
														con->ipv4_tuple.remote_port);
		if (new_sock == NULL) {
			log_error("tcp_pkt_rx: pet_socket_accepted failed\n");
			put_and_unlock_tcp_con(con);
			return -1;
		}

		con->sock = new_sock;
		add_sock_to_tcp_con(petnet_state->tcp_state->con_map, con, new_sock);

		put_and_unlock_tcp_con(con);
		return 0;
	}

	
	if (con->con_state == SYN_SENT && tcp_hdr->flags.SYN && tcp_hdr->flags.ACK) {

		pet_printf("tcp_pkt_rx: SYN_SENT got SYN-ACK -> ESTABLISHED\n");

		__clear_pending(con); 

		con->expected_seq_num = ntohl(tcp_hdr->seq_num) + 1;
		con->remote_recv_win  = ntohs(tcp_hdr->recv_win);
		con->con_state        = ESTABLISHED;

		__send_ack(con);
		pet_socket_connected(con->sock);

		put_and_unlock_tcp_con(con);
		return 0;
	}

	if (con->con_state == SYN_SENT) {
		pet_printf("tcp_pkt_rx: SYN_SENT unexpected packet, dropping\n");
		put_and_unlock_tcp_con(con);
		return 0;
	}

	
	if (con->con_state == ESTABLISHED) {

		
		con->remote_recv_win = ntohs(tcp_hdr->recv_win);

		
		if (tcp_hdr->flags.ACK) {
			uint32_t ack_val = ntohl(tcp_hdr->ack_num);

			if (con->pending_pkt != NULL && ack_val == con->next_seq_num) {
				
				pet_printf("tcp_pkt_rx: ESTABLISHED ACK for seq=%u\n", ack_val);

				
				if (con->cwnd < con->ssthresh) {
					
					con->cwnd += TCP_MSS;
				} else {
					
					con->cwnd += (TCP_MSS * TCP_MSS) / con->cwnd;
				}

				__clear_pending(con); 

				
				uint32_t waiting = pet_socket_send_capacity(con->sock);
				if (waiting > 0) {
					
					uint32_t limit = con->cwnd < con->remote_recv_win
									 ? con->cwnd : con->remote_recv_win;
					if (waiting > limit) waiting = limit;
					if (waiting > TCP_MSS) waiting = TCP_MSS; 

					uint8_t * buf = pet_malloc(waiting);
					pet_socket_sending_data(con->sock, buf, waiting);
					int sret = __send_tcp_pkt(con,
											  con->next_seq_num,
											  con->expected_seq_num,
											  0, 1, 0,
											  buf, waiting,
											  1);
					pet_free(buf);
					if (sret == 0) {
						con->next_seq_num += waiting;
					}
				}

			} else if (con->pending_pkt != NULL && ack_val == con->pending_seq_num) {
				
				con->dup_ack_cnt++;
				pet_printf("tcp_pkt_rx: dup ACK %u (cnt=%u)\n",
						   ack_val, con->dup_ack_cnt);

				if (con->dup_ack_cnt == 3) {
					
					pet_printf("tcp_pkt_rx: fast retransmit seq=%u\n",
							   con->pending_seq_num);

					
					con->ssthresh = (con->cwnd / 2 > TCP_MSS)
									? con->cwnd / 2 : TCP_MSS;
					con->cwnd = con->ssthresh;

					
					if (con->retx_timeout) {
						pet_cancel_timeout(con->retx_timeout);
						con->retx_timeout = NULL;
					}
					__retransmit_pending(con);
				}
			}
		}

		
		void     * payload     = __get_payload(pkt);
		uint32_t   payload_len = pkt->payload_len;

		if (payload_len > 0) {
			pet_printf("tcp_pkt_rx: ESTABLISHED %u bytes\n", payload_len);

			if (pet_socket_recv_capacity(con->sock) >= payload_len) {
				pet_socket_received_data(con->sock, payload, payload_len);
				con->expected_seq_num += payload_len;
			} else {
				log_error("tcp_pkt_rx: recv buffer full, dropping\n");
			}

			__send_ack(con);
		}

		
		if (tcp_hdr->flags.FIN) {
			pet_printf("tcp_pkt_rx: ESTABLISHED FIN -> CLOSE_WAIT\n");
			con->expected_seq_num += 1;
			con->con_state         = CLOSE_WAIT;
			__send_ack(con);
			pet_socket_closed(con->sock);
		}

		put_and_unlock_tcp_con(con);
		return 0;
	}

	
	if (con->con_state == FIN_WAIT1) {
		if (tcp_hdr->flags.ACK) {
			pet_printf("tcp_pkt_rx: FIN_WAIT1 ACK -> FIN_WAIT2\n");
			__clear_pending(con);
			con->con_state = FIN_WAIT2;
		}
		put_and_unlock_tcp_con(con);
		return 0;
	}

	
	if (con->con_state == FIN_WAIT2) {
		if (tcp_hdr->flags.FIN) {
			pet_printf("tcp_pkt_rx: FIN_WAIT2 FIN -> CLOSED\n");
			con->expected_seq_num += 1;
			con->con_state         = TIME_WAIT;
			__send_ack(con);
			
			con->con_state = CLOSED;
			remove_tcp_con(petnet_state->tcp_state->con_map, con);
		}
		put_and_unlock_tcp_con(con);
		return 0;
	}

	
	if (con->con_state == LAST_ACK) {
		if (tcp_hdr->flags.ACK) {
			pet_printf("tcp_pkt_rx: LAST_ACK ACK -> CLOSED\n");
			__clear_pending(con);
			con->con_state = CLOSED;
			remove_tcp_con(petnet_state->tcp_state->con_map, con);
		}
		put_and_unlock_tcp_con(con);
		return 0;
	}

	
	if (con->con_state == CLOSE_WAIT) {
		pet_printf("tcp_pkt_rx: CLOSE_WAIT, dropping\n");
		put_and_unlock_tcp_con(con);
		return 0;
	}

	pet_printf("tcp_pkt_rx: unhandled state %d, dropping\n", con->con_state);
	put_and_unlock_tcp_con(con);
	return 0;
}

int
tcp_init(struct petnet * petnet_state)
{
	struct tcp_state * state = pet_malloc(sizeof(struct tcp_state));

	state->con_map = create_tcp_con_map();

	petnet_state->tcp_state = state;

	return 0;
}