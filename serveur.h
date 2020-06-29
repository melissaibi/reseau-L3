#ifndef SERVEUR_H
#define SERVEUR_H

#include "client.h"

void parse_packet(data_list *data_l, neighbour_list *neighbour_l, unsigned char *receive, struct sockaddr_in6 *saddr, int sock);

#endif