/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <string.h>
#include <errno.h>

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


extern int petnet_errno;

struct tcp_state {
    struct tcp_con_map * con_map;
};


static uint16_t __calculate_tcp_checksum(struct packet * pkt, struct ipv4_addr * src_ip, struct ipv4_addr * dst_ip);

static inline struct tcp_raw_hdr *
__get_tcp_hdr(struct packet * pkt)
{
    struct tcp_raw_hdr * tcp_hdr = pkt->layer_2_hdr + pkt->layer_2_hdr_len + pkt->layer_3_hdr_len;

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
        pkt->payload_len = ntohs(ipv4_hdr->total_len) - (pkt->layer_3_hdr_len + pkt->layer_4_hdr_len);

        return pkt->payload;
    } else {
        log_error("Unhandled layer 3 packet format\n");
        return NULL;
    }

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

    pet_json_add_u16 (hdr_json, "src port",    ntohs(hdr->src_port));
    pet_json_add_u16 (hdr_json, "dst port",    ntohs(hdr->dst_port));
    pet_json_add_u32 (hdr_json, "seq num",     ntohl(hdr->seq_num));
    pet_json_add_u32 (hdr_json, "ack num",     ntohl(hdr->ack_num));
    pet_json_add_u8  (hdr_json, "header len",  hdr->header_len * 4);
    pet_json_add_bool(hdr_json, "URG flag",    hdr->flags.URG);
    pet_json_add_bool(hdr_json, "ACK flag",    hdr->flags.ACK);
    pet_json_add_bool(hdr_json, "PSH flag",    hdr->flags.PSH);
    pet_json_add_bool(hdr_json, "RST flag",    hdr->flags.RST);
    pet_json_add_bool(hdr_json, "SYN flag",    hdr->flags.SYN);
    pet_json_add_bool(hdr_json, "FIN flag",    hdr->flags.FIN);
    pet_json_add_u16 (hdr_json, "recv win",    ntohs(hdr->recv_win));
    pet_json_add_u16 (hdr_json, "checksum",    ntohs(hdr->checksum));
    pet_json_add_u16 (hdr_json, "urgent ptr",  ntohs(hdr->urgent_ptr));


    return hdr_json;

err:
    if (hdr_json != PET_JSON_INVALID_OBJ) pet_json_free(hdr_json);

    return PET_JSON_INVALID_OBJ;
}


void
print_tcp_header(struct tcp_raw_hdr * tcp_hdr)
{
    pet_json_obj_t hdr_json = PET_JSON_INVALID_OBJ;

    char * json_str = NULL;

    hdr_json = tcp_hdr_to_json(tcp_hdr);

    if (hdr_json == PET_JSON_INVALID_OBJ) {
        log_error("Could not serialize TCP Header to JSON\n");
        return;
    }

    json_str = pet_json_serialize(hdr_json);

    pet_printf("\"TCP Header\": %s\n", json_str);

    pet_free(json_str);
    pet_json_free(hdr_json);

    return;

}





int 
tcp_listen(struct socket * sock, struct ipv4_addr * local_addr, uint16_t local_port)
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
    if (con == NULL) {
        return -1;
    }

    con->con_state = LISTEN;

    if (add_sock_to_tcp_con(tcp_state->con_map, con, sock) != 0) {
        log_error("Failed to add socket to TCP connection map\n");
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

    (void)tcp_state; // delete me

    return -1;
}


int
tcp_send(struct socket * sock)
{
    struct tcp_state      * tcp_state = petnet_state->tcp_state;
    struct tcp_connection * con       = get_and_lock_tcp_con_from_sock(tcp_state->con_map, sock);

    if (con == NULL) {
        log_error("Could not find TCP connection for socket\n");
        return -1;
    }

    if (con->con_state != ESTABLISHED) {
        log_error("TCP connection is not established\n");
        goto err;
    }

    uint32_t data_len = pet_socket_send_capacity(sock);

    if (data_len == 0) {
        put_and_unlock_tcp_con(con);
        return 0;
    }

    /* Build data packet */
    struct packet      * pkt = create_empty_packet();
    struct tcp_raw_hdr * hdr = NULL;

    if (!pkt) goto err;

    pkt->layer_2_hdr_len = 0;
    pkt->layer_3_hdr_len = 0;
    pkt->layer_4_hdr_len = 0;
    pkt->payload_len     = 0;
    pkt->layer_2_hdr     = NULL;
    pkt->layer_3_hdr     = NULL;
    pkt->layer_4_hdr     = NULL;
    pkt->payload         = NULL;

    hdr = __make_tcp_hdr(pkt, 0);

    pkt->payload     = pet_malloc(data_len);
    pkt->payload_len = data_len;

    pet_socket_sending_data(sock, pkt->payload, data_len);

    hdr->src_port   = htons(con->ipv4_tuple.local_port);
    hdr->dst_port   = htons(con->ipv4_tuple.remote_port);
    hdr->seq_num    = htonl(con->next_seq_num);
    hdr->ack_num    = htonl(con->expected_seq_num);
    hdr->header_len = 5;
    hdr->flags.ACK  = 1;
    hdr->flags.PSH  = 1;
    hdr->recv_win   = htons(65535);
    hdr->checksum   = 0;

    pkt->layer_3_type    = IPV4_PKT;
    pkt->layer_4_type    = TCP_PKT;
    pkt->layer_4_hdr     = hdr;
    pkt->layer_4_hdr_len = 20;

    hdr->checksum = __calculate_tcp_checksum(pkt,
                                              con->ipv4_tuple.local_ip,
                                              con->ipv4_tuple.remote_ip);

    con->next_seq_num += data_len;

    if (ipv4_pkt_tx(pkt, con->ipv4_tuple.remote_ip) == -1) {
        log_error("Failed to transmit data packet\n");
        free_packet(pkt);
        goto err;
    }

    put_and_unlock_tcp_con(con);
    return 0;

    err:
        if (con) put_and_unlock_tcp_con(con);
        return -1;
}



/* Petnet assumes SO_LINGER semantics, so if we'ere here there is no pending write data */
int
tcp_close(struct socket * sock)
{
    struct tcp_state      * tcp_state = petnet_state->tcp_state;
  
    (void)tcp_state; // delete me

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

    checksum = calculate_checksum_begin(&pseudo_hdr, sizeof(struct ipv4_pseudo_hdr) / 2);
    checksum = calculate_checksum_continue(checksum, pkt->layer_4_hdr, pkt->layer_4_hdr_len / 2);

    if (pkt->payload_len > 0) {
        checksum = calculate_checksum_finalize(checksum, pkt->payload, pkt->payload_len / 2);
    } else {
        checksum = calculate_checksum_finalize(checksum, NULL, 0);
    }

    return checksum;
}


int 
tcp_pkt_rx(struct packet * pkt)
{
    if (pkt->layer_3_type != IPV4_PKT) {
        return -1;
    }

    struct tcp_raw_hdr  * tcp_hdr  = __get_tcp_hdr(pkt);
    struct ipv4_raw_hdr * ipv4_hdr = pkt->layer_3_hdr;

    /* Try exact match first */
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

    /* Fallback to wildcard listener */
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
        pet_printf("Received packet for non-existent connection, dropping\n");
        return 0;
    }

    /* ---- LISTEN: incoming SYN ---- */
    if (con->con_state == LISTEN && tcp_hdr->flags.SYN) {
        pet_printf("Received SYN for listening socket\n");

        struct socket    * serv_sock = con->sock;
        struct ipv4_addr * l_ip      = ipv4_addr_from_octets(ipv4_hdr->dst_ip);
        struct ipv4_addr * r_ip      = ipv4_addr_from_octets(ipv4_hdr->src_ip);

        struct tcp_connection * new_con = create_ipv4_tcp_con(
            petnet_state->tcp_state->con_map,
            l_ip,
            r_ip,
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
        new_con->next_seq_num     = 21;
        new_con->con_state        = SYN_RCVD;
        new_con->sock             = serv_sock;

        /* Build SYN-ACK */
        struct packet      * rsp = create_empty_packet();
        struct tcp_raw_hdr * hdr = NULL;

        if (!rsp) {
            put_and_unlock_tcp_con(new_con);
            put_and_unlock_tcp_con(con);
            return -1;
        }

        rsp->layer_2_hdr_len = 0;
        rsp->layer_3_hdr_len = 0;
        rsp->layer_4_hdr_len = 0;
        rsp->payload_len     = 0;
        rsp->layer_2_hdr     = NULL;
        rsp->layer_3_hdr     = NULL;
        rsp->layer_4_hdr     = NULL;
        rsp->payload         = NULL;

        hdr = __make_tcp_hdr(rsp, 0);

        hdr->src_port   = htons(new_con->ipv4_tuple.local_port);
        hdr->dst_port   = htons(new_con->ipv4_tuple.remote_port);
        hdr->seq_num    = htonl(new_con->next_seq_num);
        hdr->ack_num    = htonl(new_con->expected_seq_num);
        hdr->header_len = 5;
        hdr->flags.SYN  = 1;
        hdr->flags.ACK  = 1;
        hdr->recv_win   = htons(65535);
        hdr->checksum   = 0;

        rsp->layer_3_type    = IPV4_PKT;
        rsp->layer_4_type    = TCP_PKT;
        rsp->layer_4_hdr     = hdr;
        rsp->layer_4_hdr_len = 20;

        hdr->checksum = __calculate_tcp_checksum(rsp,
                                                  new_con->ipv4_tuple.local_ip,
                                                  new_con->ipv4_tuple.remote_ip);

        new_con->next_seq_num += 1;

        ipv4_pkt_tx(rsp, new_con->ipv4_tuple.remote_ip);

        put_and_unlock_tcp_con(new_con);
        put_and_unlock_tcp_con(con);
        return 0;
    }

    /* ---- SYN_RCVD: SYN retry ---- */
    if (con->con_state == SYN_RCVD && tcp_hdr->flags.SYN) {
        pet_printf("Received SYN retry, re-sending SYN-ACK\n");

        struct packet      * rsp = create_empty_packet();
        struct tcp_raw_hdr * hdr = NULL;

        if (!rsp) {
            put_and_unlock_tcp_con(con);
            return -1;
        }

        rsp->layer_2_hdr_len = 0;
        rsp->layer_3_hdr_len = 0;
        rsp->layer_4_hdr_len = 0;
        rsp->payload_len     = 0;
        rsp->layer_2_hdr     = NULL;
        rsp->layer_3_hdr     = NULL;
        rsp->layer_4_hdr     = NULL;
        rsp->payload         = NULL;

        hdr = __make_tcp_hdr(rsp, 0);

        hdr->src_port   = htons(con->ipv4_tuple.local_port);
        hdr->dst_port   = htons(con->ipv4_tuple.remote_port);
        hdr->seq_num    = htonl(con->next_seq_num - 1);
        hdr->ack_num    = htonl(con->expected_seq_num);
        hdr->header_len = 5;
        hdr->flags.SYN  = 1;
        hdr->flags.ACK  = 1;
        hdr->recv_win   = htons(65535);
        hdr->checksum   = 0;

        rsp->layer_3_type    = IPV4_PKT;
        rsp->layer_4_type    = TCP_PKT;
        rsp->layer_4_hdr     = hdr;
        rsp->layer_4_hdr_len = 20;

        hdr->checksum = __calculate_tcp_checksum(rsp,
                                                  con->ipv4_tuple.local_ip,
                                                  con->ipv4_tuple.remote_ip);

        ipv4_pkt_tx(rsp, con->ipv4_tuple.remote_ip);

        put_and_unlock_tcp_con(con);
        return 0;
    }

    /* ---- SYN_RCVD: final ACK -> ESTABLISHED ---- */
    if (con->con_state == SYN_RCVD && tcp_hdr->flags.ACK) {
        pet_printf("Received ACK for SYN-ACK, connection ESTABLISHED\n");

        con->con_state = ESTABLISHED;

        struct socket * new_sock = pet_socket_accepted(con->sock,
                                                        con->ipv4_tuple.remote_ip,
                                                        con->ipv4_tuple.remote_port);
        if (new_sock == NULL) {
            log_error("Failed to accept connection\n");
            put_and_unlock_tcp_con(con);
            return -1;
        }

        con->sock = new_sock;
        add_sock_to_tcp_con(petnet_state->tcp_state->con_map, con, new_sock);

        put_and_unlock_tcp_con(con);
        return 0;
    }

    /* ---- ESTABLISHED: data packet ---- */
    if (con->con_state == ESTABLISHED) {

        void * payload     = __get_payload(pkt);
        int    payload_len = pkt->payload_len;

        if (payload_len > 0) {
            pet_printf("Received %d bytes of data\n", payload_len);

            con->expected_seq_num += payload_len;

            /* Send ACK */
            struct packet      * ack     = create_empty_packet();
            struct tcp_raw_hdr * ack_hdr = NULL;

            if (!ack) {
                put_and_unlock_tcp_con(con);
                return -1;
            }

            ack->layer_2_hdr_len = 0;
            ack->layer_3_hdr_len = 0;
            ack->layer_4_hdr_len = 0;
            ack->payload_len     = 0;
            ack->layer_2_hdr     = NULL;
            ack->layer_3_hdr     = NULL;
            ack->layer_4_hdr     = NULL;
            ack->payload         = NULL;

            ack_hdr = __make_tcp_hdr(ack, 0);

            ack_hdr->src_port   = htons(con->ipv4_tuple.local_port);
            ack_hdr->dst_port   = htons(con->ipv4_tuple.remote_port);
            ack_hdr->seq_num    = htonl(con->next_seq_num);
            ack_hdr->ack_num    = htonl(con->expected_seq_num);
            ack_hdr->header_len = 5;
            ack_hdr->flags.ACK  = 1;
            ack_hdr->recv_win   = htons(65535);
            ack_hdr->checksum   = 0;

            ack->layer_3_type    = IPV4_PKT;
            ack->layer_4_type    = TCP_PKT;
            ack->layer_4_hdr     = ack_hdr;
            ack->layer_4_hdr_len = 20;

            ack_hdr->checksum = __calculate_tcp_checksum(ack,
                                                          con->ipv4_tuple.local_ip,
                                                          con->ipv4_tuple.remote_ip);

            pet_socket_received_data(con->sock, payload, payload_len);
            ipv4_pkt_tx(ack, con->ipv4_tuple.remote_ip);
        }

        put_and_unlock_tcp_con(con);
        return 0;
    }

    /* Default: unknown state, just release */
    put_and_unlock_tcp_con(con);
    return 0;
}

int
tcp_init(struct petnet * petnet_state)
{
    struct tcp_state * state = pet_malloc(sizeof(struct tcp_state));

    state->con_map  = create_tcp_con_map();

    petnet_state->tcp_state = state;
    
    return 0;
}
