#ifndef CLIENT_H
#define CLIENT_H

#include "list.h"

#define MAXLINE 1024

#define PAD1 0
#define PADN 1
#define NEIGHBOUR_REQ 2
#define NEIGHBOUR 3
#define NETWORK_HASH 4
#define NETWORK_STATE_REQ 5
#define NODE_HASH 6
#define NODE_STATE_REQ 7
#define NODE_STATE 8
#define WARNING 9

#define U8 sizeof(uint8_t)
#define U16 sizeof(uint16_t)
#define UU64 sizeof(uint64_t)

unsigned char *get_random_dev();
unsigned char *build_header();
unsigned char *build_pad1();
unsigned char *build_padN(uint8_t length);
unsigned char *build_neighbour_req();
unsigned char *build_neighbour(unsigned char *ip, uint16_t port);
unsigned char *build_network_state_req();
unsigned char *build_network_hash(unsigned char *network_hash);
unsigned char *build_node_hash(data *d);
unsigned char *build_node_state_request(unsigned char *id);
unsigned char *build_node_state(data *d);
unsigned char *build_warning(char *msg);
void add_tlv(unsigned char *header, unsigned char *tlv);
void send_datagram(int sock, struct sockaddr_in6 *saddr, unsigned char *datagram);
void hash_node_data(data *d);
void hash_data(data *d, unsigned char *hash);
void calculate_network_hash(data_list *list, unsigned char *hash);
int packet_length(unsigned char *packet);
void inondation_process(neighbour_list *neighbour_l, data_list *data_l, int sock);

#endif