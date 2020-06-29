#ifndef MAIN_H
#define MAIN_H

#define _GNU_SOURCE
#include "interface.h"
#define SRC_PORT 1717

pthread_mutex_t mutex_neighbour;
pthread_mutex_t mutex_data;

int sock_send = 0;
struct sockaddr_in6 saddr;
int DEBUG = 0;

unsigned char my_id[8];
uint16_t my_seqno;

neighbour_list *neighbour_l = NULL;
data_list *data_l = NULL;

bool pthread_innondation_exit = false;
bool pthread_server_exit = false;

FILE *fp;

void get_server_address(char *hostname, char *port, struct sockaddr_in6 *saddr);

static void *fn_serveur(void *p_data);

static void *fn_innondation(void *p_data);

void get_mac_adress(unsigned char *mac_address);

#endif