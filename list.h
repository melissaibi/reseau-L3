#ifndef LIST_H
#define LIST_H

extern int DEBUG;

#define L_ERROR 0
#define L_DEBUG 1
#define L_TRACE 2

#define DEBUG_PRINT(X, fp, ...)   \
    if (DEBUG >= X)               \
    {                             \
        fprintf(fp, __VA_ARGS__); \
        fflush(fp);               \
    }

#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <math.h>
#include <unistd.h>
#include <limits.h>
#include <stdbool.h>
#include <ctype.h>
#include "openssl/sha.h"
#include "pthread.h"
#include "ifaddrs.h"

#ifndef SIOCGIFHWADDR
#include <net/if_dl.h>
#endif

extern pthread_mutex_t mutex_neighbour;
extern pthread_mutex_t mutex_data;

extern bool pthread_innondation_exit;
extern bool pthread_server_exit;

extern unsigned char my_id[8];
extern FILE *fp;
extern FILE *fp1;
extern int sock_send;

typedef struct neighbour
{
    struct sockaddr_in6 adress;
    time_t last_packet_date;
    bool permanent;
} neighbour;

typedef struct neighbour_node
{
    neighbour *current;
    struct neighbour_node *next;
    struct neighbour_node *prev;
} neighbour_node;

typedef struct neighbour_list
{
    int length;
    neighbour_node *tail;
    neighbour_node *head;
} neighbour_list;

bool compare_ip_adress(struct in6_addr *ip1, struct in6_addr *ip2);

int get_randint(int a, int b);

neighbour_list *init_neighbour_list(void);

neighbour *random_neighbour(neighbour_list *target);

bool contain_neighbour(neighbour_list *target, struct sockaddr_in6 *addr);

neighbour *get_neighbour(neighbour_list *target, struct sockaddr_in6 *addr);

neighbour *get_neighbour_from_index(neighbour_list *target, int i);

void print_neighbour_list(neighbour_list *list);

void destroy_neighbour_list(neighbour_list *list);

neighbour_list *append_neighbour_list(neighbour_list *target, neighbour *c);

neighbour_list *neighbour_list_remove_all(neighbour_list *list, struct sockaddr_in6 *addr);

neighbour_list *neighbnour_list_remove(neighbour_list *list, struct sockaddr_in6 *addr);

typedef struct data
{

    unsigned char node_id[8];
    uint16_t seqno;
    time_t last_update;
    unsigned char msg[192];
    uint8_t msg_length;
    unsigned char hash[16];
} data;

typedef struct data_node
{
    data *current;
    struct data_node *next;
    struct data_node *prev;
} data_node;

typedef struct data_list
{
    int length;
    data_node *tail;
    data_node *head;
} data_list;

data_list *init_data_list(void);

void print_data_list(data_list *list);

void destroy_data_list(data_list *list);

void bubble_sort_data_bytime(data_list *target);

data *get_node_data(data_list *target, unsigned char *node_id);

data_list *append_data_list(data_list *target, data *d);

data_list *append_data_list_sort(data_list *target, data *d);

data_list *data_list_remove_all(data_list *list, unsigned char *node_id);

data_list *data_list_remove(data_list *list, unsigned char *node_id);

#endif