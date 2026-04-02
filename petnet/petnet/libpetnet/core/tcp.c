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
    struct tcp_state * tcp_state = petnet_state->tcp_state;
    
    // 1. Create a wildcard address (0.0.0.0) for the remote side
    struct ipv4_addr wildcard;
    memset(&wildcard, 0, sizeof(struct ipv4_addr));

    // 2. Create the connection object
    // Note: If your create_ipv4_tcp_con implementation does not malloc the 
    // internal tuple pointers, we will verify/fix that here.
    struct tcp_connection * con = create_ipv4_tcp_con(tcp_state->con_map, 
                                                      local_addr, 
                                                      &wildcard, 
                                                      local_port, 
                                                      0);
    
    if (con) {
        con->con_state = LISTEN;

        /* --- FIX: ENSURE TUPLE POINTERS HAVE MEMORY --- */
        
        // Ensure local_ip has a home and copy the data
        if (con->ipv4_tuple.local_ip == NULL) {
            con->ipv4_tuple.local_ip = pet_malloc(sizeof(struct ipv4_addr));
        }
        if (local_addr) {
            memcpy(con->ipv4_tuple.local_ip, local_addr, sizeof(struct ipv4_addr));
        } else {
            memset(con->ipv4_tuple.local_ip, 0, sizeof(struct ipv4_addr));
        }

        // Ensure remote_ip has a home (even for a listener, it shouldn't be a dangling pointer)
        if (con->ipv4_tuple.remote_ip == NULL) {
            con->ipv4_tuple.remote_ip = pet_malloc(sizeof(struct ipv4_addr));
            memset(con->ipv4_tuple.remote_ip, 0, sizeof(struct ipv4_addr));
        }
        /* ---------------------------------------------- */

        if (add_sock_to_tcp_con(tcp_state->con_map, con, sock) != 0) {
            log_error("Failed to add socket to TCP connection map\n");
            remove_tcp_con(tcp_state->con_map, con);
            put_and_unlock_tcp_con(con);
            return -1;
        }

        put_and_unlock_tcp_con(con);
        return 0;
    }

    return -1;
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

    (void)tcp_state; // delete me

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






int 
tcp_pkt_rx(struct packet * pkt)
{
    if (pkt->layer_3_type == IPV4_PKT) {

        // 1. Extract Headers
        struct tcp_raw_hdr  * tcp_hdr  = __get_tcp_hdr(pkt);
        struct ipv4_raw_hdr * ipv4_hdr = pkt->layer_3_hdr;

        // 2. Multi-Stage Lookup
        // Try Exact Match first
        struct tcp_connection * con = get_and_lock_tcp_con_from_ipv4(
            petnet_state->tcp_state->con_map,
            (struct ipv4_addr *)ipv4_hdr->dst_ip,
            (struct ipv4_addr *)ipv4_hdr->src_ip,
            ntohs(tcp_hdr->dst_port),
            ntohs(tcp_hdr->src_port)
        );

        // Fallback to Wildcard (Listener) if exact match fails
        if (!con) {
            struct ipv4_addr wildcard;
            memset(&wildcard, 0, sizeof(struct ipv4_addr));

            con = get_and_lock_tcp_con_from_ipv4(
                petnet_state->tcp_state->con_map,
                &wildcard, // Local Wildcard
                &wildcard, // Remote Wildcard
                ntohs(tcp_hdr->dst_port),
                0          // Remote port 0
            );
        }

        // 3. Handle SYN (Passive Open / LISTEN State)
        if (con && con->con_state == LISTEN && tcp_hdr->flags.SYN) {
            pet_printf("Received SYN for listening socket\n");

            /* --- CRITICAL: POINTER MEMORY ALLOCATION --- */
            // Since your struct defines these as POINTERS, we must allocate heap memory
            if (con->ipv4_tuple.remote_ip == NULL) {
                con->ipv4_tuple.remote_ip = pet_malloc(sizeof(struct ipv4_addr));
            }
            if (con->ipv4_tuple.local_ip == NULL) {
                con->ipv4_tuple.local_ip = pet_malloc(sizeof(struct ipv4_addr));
            }

            // Copy data into our new heap-allocated memory
            memcpy(con->ipv4_tuple.remote_ip, ipv4_hdr->src_ip, sizeof(struct ipv4_addr));
            memcpy(con->ipv4_tuple.local_ip,  ipv4_hdr->dst_ip, sizeof(struct ipv4_addr));

            con->ipv4_tuple.remote_port = ntohs(tcp_hdr->src_port);
            con->ipv4_tuple.local_port  = ntohs(tcp_hdr->dst_port);

            // TCP Handshake Bookkeeping
            con->expected_seq_num = ntohl(tcp_hdr->seq_num) + 1;
            con->next_seq_num     = 21; // Our Initial Sequence Number
            con->con_state        = SYN_RCVD;

            // 4. Build SYN-ACK Response
            struct packet * response_pkt = create_empty_packet();
            if (!response_pkt) {
                put_and_unlock_tcp_con(con);
                return -1;
            }

            struct tcp_raw_hdr * outgoing_hdr = __make_tcp_hdr(response_pkt, 0);

            outgoing_hdr->src_port   = htons(con->ipv4_tuple.local_port);
            outgoing_hdr->dst_port   = htons(con->ipv4_tuple.remote_port);
            outgoing_hdr->seq_num    = htonl(con->next_seq_num);
            outgoing_hdr->ack_num    = htonl(con->expected_seq_num);
            outgoing_hdr->header_len = 5; // 20 bytes
            outgoing_hdr->flags.SYN  = 1;
            outgoing_hdr->flags.ACK  = 1;
            outgoing_hdr->recv_win   = htons(65535);
            outgoing_hdr->checksum   = 0; 

            /* --- CRITICAL: PACKET METADATA --- */
            // If you don't set these, ipv4_pkt_tx will SegFault during ARP/TX
            response_pkt->layer_3_type    = IPV4_PKT;
            response_pkt->layer_4_type    = TCP_PKT;
            response_pkt->layer_4_hdr     = outgoing_hdr;
            response_pkt->layer_4_hdr_len = 20;

            // 5. Send SYN-ACK 
            // Pass the pointer DIRECTLY (it points to the struct in the heap)
            ipv4_pkt_tx(response_pkt, con->ipv4_tuple.remote_ip);

            con->next_seq_num += 1; // SYN flag consumes 1 sequence number
            put_and_unlock_tcp_con(con);
            return 0;
        }

        // ADD THIS CASE: Handle a SYN retry for a connection already in SYN_RCVD
        // Handle a SYN retry for a connection already in SYN_RCVD
        else if (con && con->con_state == SYN_RCVD && tcp_hdr->flags.SYN) {
            pet_printf("Received SYN retry, re-sending SYN-ACK\n");
            
            struct packet * response_pkt = create_empty_packet();
            if (!response_pkt) {
                put_and_unlock_tcp_con(con);
                return -1;
            }

            struct tcp_raw_hdr * outgoing_hdr = __make_tcp_hdr(response_pkt, 0);
            
            // FILL IN THE HEADERS (This makes the variable 'used')
            outgoing_hdr->src_port   = htons(con->ipv4_tuple.local_port);
            outgoing_hdr->dst_port   = htons(con->ipv4_tuple.remote_port);
            outgoing_hdr->seq_num    = htonl(con->next_seq_num - 1); // Use the ISN we already picked
            outgoing_hdr->ack_num    = htonl(con->expected_seq_num);
            outgoing_hdr->header_len = 5; 
            outgoing_hdr->flags.SYN  = 1;
            outgoing_hdr->flags.ACK  = 1;
            outgoing_hdr->recv_win   = htons(65535);
            outgoing_hdr->checksum   = 0; 

            // Initialize metadata so the IP layer doesn't crash
            response_pkt->layer_3_type    = IPV4_PKT;
            response_pkt->layer_4_type    = TCP_PKT;
            response_pkt->layer_4_hdr     = outgoing_hdr;
            response_pkt->layer_4_hdr_len = 20;
            
            ipv4_pkt_tx(response_pkt, con->ipv4_tuple.remote_ip);
            
            put_and_unlock_tcp_con(con);
            return 0;
        }

        // 6. Handle Final ACK (Transition to ESTABLISHED)
        else if (con && con->con_state == SYN_RCVD && tcp_hdr->flags.ACK) {
            pet_printf("Received ACK for SYN-ACK we sent\n");
            
            con->con_state = ESTABLISHED;
            
            put_and_unlock_tcp_con(con);
            return 0;
        }

        // 7. Cleanup/Default Case
        else if (con) {
            put_and_unlock_tcp_con(con);
            return 0;
        } else {
            pet_printf("Received packet for non-existent connection, dropping\n");
            return 0;
        }
    }
    return -1;
}
int
tcp_init(struct petnet * petnet_state)
{
    struct tcp_state * state = pet_malloc(sizeof(struct tcp_state));

    state->con_map  = create_tcp_con_map();

    petnet_state->tcp_state = state;
    
    return 0;
}
