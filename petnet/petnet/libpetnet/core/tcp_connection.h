/*
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#ifndef __TCP_CON_MAP_H__
#define __TCP_CON_MAP_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <pthread.h>

#include <util/ip_address.h>

struct socket;
struct tcp_con_map;

typedef enum { CLOSED      = 0,
			   LISTEN      = 1,
			   SYN_RCVD    = 2,
			   SYN_SENT    = 3, 
			   ESTABLISHED = 4,
			   CLOSE_WAIT  = 5,
			   FIN_WAIT1   = 6,
			   CLOSING     = 7,
			   LAST_ACK    = 8,
			   FIN_WAIT2   = 9,
			   TIME_WAIT   = 10 } tcp_con_state_t;

struct tcp_con_ipv4_tuple {
	struct ipv4_addr * local_ip;
	struct ipv4_addr * remote_ip;
	uint16_t           local_port;
	uint16_t           remote_port;
};

struct tcp_connection {
	
	ip_net_type_t net_type;

	union {
		struct tcp_con_ipv4_tuple ipv4_tuple;
	};

	int ref_cnt;

	pthread_mutex_t con_lock;

	struct socket * sock;

	

	
	uint32_t ack_num;
	
	uint32_t next_seq_num;
	
	uint32_t expected_seq_num;

	
	uint8_t         * pending_pkt;        
	uint32_t          pending_pkt_len;
	uint32_t          pending_seq_num;
	uint64_t          pending_pkt_sent_time;  
	struct pet_timeout * retx_timeout;

	
	uint32_t remote_recv_win;

	
	uint32_t cwnd;
	uint32_t ssthresh;
	uint32_t dup_ack_cnt;

	tcp_con_state_t con_state;
};

struct tcp_connection * 
get_and_lock_tcp_con_from_sock(struct tcp_con_map * map,
							   struct socket      * socket);

struct tcp_connection *
get_and_lock_tcp_con_from_ipv4(struct tcp_con_map * map,
							   struct ipv4_addr   * local_ip, 
							   struct ipv4_addr   * remote_ip,
							   uint16_t             local_port,
							   uint16_t             remote_port);

void 
put_and_unlock_tcp_con(struct tcp_connection * con);

struct tcp_connection *
create_ipv4_tcp_con(struct tcp_con_map * map,
					struct ipv4_addr   * local_ip, 
					struct ipv4_addr   * remote_ip,
					uint16_t             local_port,
					uint16_t             remote_port);

int 
add_sock_to_tcp_con(struct tcp_con_map    * map,
					struct tcp_connection * con, 
					struct socket         * new_sock);

void
remove_tcp_con(struct tcp_con_map    * map,
			   struct tcp_connection * con);

int lock_tcp_con(struct tcp_connection * con);

int unlock_tcp_con(struct tcp_connection * con);

struct tcp_connection *
get_tcp_con(struct tcp_connection * con);

void
put_tcp_con(struct tcp_connection * con);

struct tcp_con_map * create_tcp_con_map();

#if 0

struct tcp_connection *
get_and_lock_tcp_con_from_ipv6(struct tcp_con_map * map,
							   struct ipv6_addr   * src_ip, 
							   struct ipv6_addr   * dst_ip,
							   uint16_t             src_port,
							   uint16_t             dst_port);

#endif

#ifdef __cplusplus
}
#endif

#endif