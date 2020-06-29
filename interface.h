#ifndef INTERFACE_H
#define INTERFACE_H

#define CO "\033[1;36m"
#define COO "\033[0m"

#include "serveur.h"

void manual();

void packet_process();

void skip_input(FILE *stream);

void user_interface_debug(neighbour_list *neighbour_l, data_list *data_l, int sock);

void user_interface(neighbour_list *neighbour_l, data_list *data_l);

#endif