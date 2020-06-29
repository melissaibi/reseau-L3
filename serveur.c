#include "serveur.h"

void parse_packet(data_list *data_l, neighbour_list *neighbour_l, unsigned char *receive, struct sockaddr_in6 *saddr, int sock)
{
    DEBUG_PRINT(L_DEBUG, fp, "\nEntering in parse packet function.\n");
    if (receive[0] == 95 && receive[1] == 1)
    {
        DEBUG_PRINT(L_DEBUG, fp, "Packet header is correct.\n");

        /* Add verification for my adress.*/

        /* Already too many neighbours.*/
        if (neighbour_l->length >= 15)
        {
            DEBUG_PRINT(L_DEBUG, fp, "Packet ignored, neighbour list already too big ! (more than 15 entries).\n\n");
            return;
        }
        /* Enough storage to add a new neighbour.*/
        else if (neighbour_l->length < 15)
        {
            /* Verifying if already in by ip adress comparison.*/
            pthread_mutex_lock(&mutex_neighbour);
            neighbour *find = get_neighbour(neighbour_l, saddr);
            pthread_mutex_unlock(&mutex_neighbour);

            if (find == NULL)
            {
                /* Neighbour is not in, adding it as a new neighbour.*/
                DEBUG_PRINT(L_DEBUG, fp, "Neighbour not found in list.\n\n");

                neighbour *new_neighbour = malloc(sizeof(neighbour));
                new_neighbour->adress = *saddr;
                new_neighbour->permanent = false;
                new_neighbour->last_packet_date = time(0);

                pthread_mutex_lock(&mutex_neighbour);
                append_neighbour_list(neighbour_l, new_neighbour);
                pthread_mutex_unlock(&mutex_neighbour);

                DEBUG_PRINT(L_DEBUG, fp, "New neighbour added.\n\n");
            }
            else
            {
                find->last_packet_date = time(0);
                DEBUG_PRINT(L_DEBUG, fp, "Neighbour already in neighbour list.\n\n");
                DEBUG_PRINT(L_DEBUG, fp, "Just updating time of last receipt.\n\n");
            }
        }

        /* We'll start analysing tlv's.*/
        int i = 4;
        uint16_t bodylength;
        memcpy(&bodylength, receive + 2 * U8, U16);
        bodylength = ntohs(bodylength);
        if (bodylength + 4 > MAXLINE)
        {
            DEBUG_PRINT(L_DEBUG, fp, "Size of packet found too big, ignoring this packet.\n");

            unsigned char *my_warning = build_warning("Packet ignored, size announced too big.\n");
            unsigned char *datagram = build_header();

            add_tlv(datagram, my_warning);
            send_datagram(sock, saddr, datagram);
            return;
        }
        while (i < bodylength + 4)
        {
            switch (receive[i])
            {
            case PAD1:
            {
                DEBUG_PRINT(L_DEBUG, fp, "pad1 received and ignored.\n\n");
                i += U8;
                break;
            }

            case PADN:
            {
                DEBUG_PRINT(L_DEBUG, fp, "padN received ignored.\n\n");
                i += U8;
                i += receive[i];
                break;
            }
            case NEIGHBOUR_REQ:
            {
                DEBUG_PRINT(L_DEBUG, fp, "TLV neighbour request received.\n\n");
                i += U8;
                pthread_mutex_lock(&mutex_neighbour);
                neighbour *random_neigh = random_neighbour(neighbour_l);
                pthread_mutex_unlock(&mutex_neighbour);

                unsigned char ip_adress[16];
                memcpy(ip_adress, &random_neigh->adress.sin6_addr, 16);

                unsigned char *neighbour = build_neighbour(ip_adress, random_neigh->adress.sin6_port);

                unsigned char *datagram = build_header();
                add_tlv(datagram, neighbour);
                send_datagram(sock, saddr, datagram);

                break;
            }
            case NEIGHBOUR:
            {
                DEBUG_PRINT(L_DEBUG, fp, "TLV neighbour received.\n\n");
                i += U8;
                i += U8;

                /* Taking all information from TLV neighbour received and creating an adress.*/
                unsigned char ip[16];
                memcpy(ip, receive + i, 16);
                i += 16;
                DEBUG_PRINT(L_TRACE, fp, "Ip adress :");
                for (int a = 0; a < 16; a++)
                {
                    DEBUG_PRINT(L_TRACE, fp, "%x ", ip[a]);
                }
                DEBUG_PRINT(L_TRACE, fp, ".\n\n");

                uint16_t port;
                memcpy(&port, receive + i, U16);

                DEBUG_PRINT(L_TRACE, fp, "Port : %d.\n", port);
                i += U16;

                struct in6_addr sin;
                memcpy(&sin, ip, 16);

                struct sockaddr_in6 neighbour_adress;
                memset(&neighbour_adress, 0, sizeof(neighbour_adress));
                neighbour_adress.sin6_addr = sin;
                neighbour_adress.sin6_family = AF_INET6;
                neighbour_adress.sin6_port = port;

                DEBUG_PRINT(L_DEBUG, fp, "Adress of neighbour created.\n");

                unsigned char my_network_hash[16];
                pthread_mutex_lock(&mutex_data);
                calculate_network_hash(data_l, my_network_hash);
                pthread_mutex_unlock(&mutex_data);

                unsigned char *tlv_network_hash = build_network_hash(my_network_hash);

                unsigned char *datagram = build_header();
                add_tlv(datagram, tlv_network_hash);
                send_datagram(sock, &neighbour_adress, datagram);
                break;
            }
            case NETWORK_HASH:
            {
                DEBUG_PRINT(L_DEBUG, fp, "TLV network hash received.\n\n");
                i += U8;
                i += U8;

                unsigned char network_hash_received[16];
                memset(network_hash_received, 0, 16);
                memcpy(network_hash_received, receive + i, 16);

                DEBUG_PRINT(L_TRACE, fp, "Network hash received : ");
                for (int a = 0; a < 16; a++)
                {
                    DEBUG_PRINT(L_TRACE, fp, "%x ", network_hash_received[a]);
                }
                DEBUG_PRINT(L_TRACE, fp, ".\n\n");

                unsigned char ip_adress[16];
                memcpy(ip_adress, &saddr->sin6_addr, 16);

                DEBUG_PRINT(L_TRACE, fp, "From ip : ");
                for (int b = 0; b < 16; b++)
                {
                    DEBUG_PRINT(L_TRACE, fp, "%x ", ip_adress[b]);
                }
                DEBUG_PRINT(L_TRACE, fp, ".\n\n");

                unsigned char my_network_hash[16];
                pthread_mutex_lock(&mutex_data);
                calculate_network_hash(data_l, my_network_hash);
                pthread_mutex_unlock(&mutex_data);

                DEBUG_PRINT(L_TRACE, fp, "My network hash : ");
                for (int c = 0; c < 16; c++)
                {
                    DEBUG_PRINT(L_TRACE, fp, "%x ", my_network_hash[c]);
                }
                DEBUG_PRINT(L_TRACE, fp, ".\n\n");

                /* Network hash received has converged, datas are stabilised.*/
                if (memcmp(network_hash_received, my_network_hash, 16) == 0)
                {
                    DEBUG_PRINT(L_DEBUG, fp, "Both network hashes converged, same network hashes !\n\n");
                }
                else
                {
                    /* We need to send a network state request because of different network hashes.*/
                    DEBUG_PRINT(L_DEBUG, fp, "Different network hashes, sending network state request.\n\n");

                    unsigned char *network_state_req = build_network_state_req();
                    unsigned char *datagram = build_header();

                    add_tlv(datagram, network_state_req);
                    send_datagram(sock, saddr, datagram);
                }

                i += 16;
                break;
            }
            case NETWORK_STATE_REQ:
            {
                DEBUG_PRINT(L_DEBUG, fp, "TLV Network state request received.\n\n");
                i += U8;

                pthread_mutex_lock(&mutex_data);
                data_node *tmp = data_l->head;

                while (tmp)
                {

                    unsigned char *datagram = build_header();
                    uint16_t bodylength = 0;

                    /* 28 is the size of a TLV node hash.*/
                    while (tmp && bodylength + 4 + 28 <= MAXLINE)
                    {
                        unsigned char *node_hash = build_node_hash(tmp->current);
                        add_tlv(datagram, node_hash);

                        memcpy(&bodylength, datagram + 2 * U8, U16);
                        bodylength = ntohs(bodylength);

                        tmp = tmp->next;
                    }

                    send_datagram(sock, saddr, datagram);

                    DEBUG_PRINT(L_DEBUG, fp, "My data node hashe/s have been sent.\n");
                }

                i += U8;
                pthread_mutex_unlock(&mutex_data);
                break;
            }
            case NODE_HASH:
            {
                DEBUG_PRINT(L_DEBUG, fp, "TLV node hash received.\n\n");
                i += 2 * U8;

                unsigned char node_id_received[8];
                memcpy(node_id_received, receive + i, 8);
                DEBUG_PRINT(L_TRACE, fp, "Node id received : ");
                for (int a = 0; a < 8; a++)
                {
                    DEBUG_PRINT(L_TRACE, fp, "%x ", node_id_received[a]);
                }
                DEBUG_PRINT(L_TRACE, fp, ".\n\n");

                i += 8;
                uint16_t seqno_received;
                memcpy(&seqno_received, receive + i, U16);

                DEBUG_PRINT(L_TRACE, fp, "Seqno received %d.\n", ntohs(seqno_received));
                i += U16;

                unsigned char node_hash_receieved[16];
                memcpy(node_hash_receieved, receive + i, 16);
                DEBUG_PRINT(L_TRACE, fp, "Node hash received : ");
                for (int z = 0; z < 16; z++)
                {
                    DEBUG_PRINT(L_TRACE, fp, "%x ", node_hash_receieved[z]);
                }
                DEBUG_PRINT(L_TRACE, fp, ".\n");

                i += 16;

                pthread_mutex_lock(&mutex_data);
                data *d = malloc(sizeof(data));
                d = get_node_data(data_l, node_id_received);

                /* If we got the data for this id and the same network hash.*/
                if (d && (memcmp(d->hash, node_hash_receieved, 16)) == 0)
                {
                    DEBUG_PRINT(L_DEBUG, fp, "Same hash for node data, nothing has to be done.\n");
                }
                else
                {
                    /* Hashes different for this node hash.*/
                    DEBUG_PRINT(L_DEBUG, fp, "Hashes differents for this node or no data found, sending node state request.\n");

                    unsigned char *node_state_req = build_node_state_request(node_id_received);
                    unsigned char *datagram = build_header();

                    add_tlv(datagram, node_state_req);
                    send_datagram(sock, saddr, datagram);
                }
                pthread_mutex_unlock(&mutex_data);
                break;
            }
            case NODE_STATE_REQ:
            {
                DEBUG_PRINT(L_DEBUG, fp, "TLV node state request received.\n\n");
                i += U8;
                i += U8;

                unsigned char node_id_received[8];
                memcpy(node_id_received, receive + i, 8);

                DEBUG_PRINT(L_TRACE, fp, "Node id received : ");
                for (int a = 0; a < 8; a++)
                {
                    DEBUG_PRINT(L_TRACE, fp, "%x ", node_id_received[a]);
                }
                DEBUG_PRINT(L_TRACE, fp, ".\n\n");

                pthread_mutex_lock(&mutex_data);
                data *d = get_node_data(data_l, node_id_received);

                /* If we got it in our list, we send a node state for this node.*/
                if (d)
                {
                    unsigned char *node_state = build_node_state(d);
                    unsigned char *datagram = build_header();

                    add_tlv(datagram, node_state);
                    send_datagram(sock, saddr, datagram);
                }
                else
                {
                    /* We don't have it.*/
                    DEBUG_PRINT(L_DEBUG, fp, "Corresponding data for this id not found in data list.\n\n");
                }

                i += 8;
                pthread_mutex_unlock(&mutex_data);
                break;
            }
            case NODE_STATE:
            {
                DEBUG_PRINT(L_DEBUG, fp, "TLV node state received.\n\n");
                i += U8;

                uint8_t node_state_length;
                memset(&node_state_length, 0, U8);
                memcpy(&node_state_length, receive + i, U8);

                i += U8;

                pthread_mutex_lock(&mutex_data);
                data *data_received = malloc(sizeof(data));
                memcpy(data_received->node_id, receive + i, UU64);

                DEBUG_PRINT(L_TRACE, fp, "Node id received : ");
                for (int a = 0; a < 8; a++)
                {
                    DEBUG_PRINT(L_TRACE, fp, "%x ", data_received->node_id[a]);
                }
                DEBUG_PRINT(L_TRACE, fp, ".\n\n");

                i += UU64;

                memcpy(&(data_received->seqno), receive + i, U16);
                i += U16;

                memcpy(data_received->hash, receive + i, 16);
                i += 16;

                data_received->msg_length = node_state_length - UU64 - U16 - 16;

                memcpy(data_received->msg, receive + i, data_received->msg_length);

                unsigned char data_hash[16];
                hash_data(data_received, data_hash);

                /* Recalculating hash for node received, if they aren't the same, send a warning.*/
                if (memcmp(data_hash, data_received->hash, 16) != 0)
                {
                    DEBUG_PRINT(L_DEBUG, fp, "Warning for node state, hash recalculated and not the same.\n");
                    unsigned char *my_warning = build_warning("Wrong node hash for node state.\n");
                    unsigned char *datagram = build_header();

                    add_tlv(datagram, my_warning);
                    send_datagram(sock, saddr, datagram);
                }
                else
                {
                    data *data = NULL;
                    data = get_node_data(data_l, data_received->node_id);

                    /* If found in data list and same hash, nothing has to be done.*/
                    if ((data != NULL) && memcmp(data->hash, data_received->hash, 16) == 0)
                    {
                        DEBUG_PRINT(L_DEBUG, fp, "Same hash for node , nothing to do.\n");
                    }
                    else if (data != NULL)
                    {
                        /* If we don't have it in our list.*/
                        uint16_t rcv_seqno = ntohs(data_received->seqno);
                        uint16_t m_seqno = ntohs(data->seqno);

                        DEBUG_PRINT(L_DEBUG, fp, "Seqno is %d , received is : %d.\n", m_seqno, rcv_seqno);

                        /* First case it is my id, so we have to update ourselves if we have a seqno < seqno received.*/
                        if (memcmp(data->node_id, my_id, 8) == 0)
                        {
                            /* I am not up to date so i add seqno received + 1 to my data.*/
                            if (((rcv_seqno - m_seqno) % 65535) < 32768)
                            {
                                m_seqno = (rcv_seqno + 1) % 65535;
                                data->seqno = htons(m_seqno);
                                hash_node_data(data);

                                DEBUG_PRINT(L_DEBUG, fp, "Seqno is not up to date, updating it : %d.\n", m_seqno);
                            }
                            else
                            {
                                /* Im a up to date for my id.*/
                                DEBUG_PRINT(L_DEBUG, fp, "Seqno is greater, i am already up to date.\n");
                            }
                        }
                        else if ((((rcv_seqno - m_seqno) % 65536) < 32768))
                        {
                            DEBUG_PRINT(L_DEBUG, fp, "About to remove from data list.\n");
                            /* We have a wrong seqno, so we replace it with the data received.*/
                            data_list_remove(data_l, data->node_id);
                            DEBUG_PRINT(L_DEBUG, fp, "Replace node data, adding to my data list.\n");
                            data_received->last_update = time(0);
                            append_data_list_sort(data_l, data_received);
                            data_received = NULL;
                        }
                        else
                        {
                            /* Our seqno is already up to date for this node, nothing to do.*/
                            DEBUG_PRINT(L_DEBUG, fp, "Nothing to do, because of node sequence already up-to-date.\n");
                        }
                    }
                    else
                    {
                        DEBUG_PRINT(L_DEBUG, fp, "Adding new node data to data list.\n");
                        data_received->last_update = time(0);
                        append_data_list_sort(data_l, data_received);
                        data_received = NULL;
                    }
                }

                pthread_mutex_unlock(&mutex_data);
                /* We have consumed data_received created above, free it.*/
                if (data_received != NULL)
                {
                    free(data_received);
                }
                i += node_state_length - UU64 - U16 - 16;
                break;
            }
            case WARNING:
            {
                DEBUG_PRINT(L_DEBUG, fp, "warning received\n\n");
                i += U8;
                /* Displaying warning received.*/
                unsigned char *warning = malloc(receive[i]);
                memset(warning, 0, receive[i]);
                memcpy(warning, receive + i + U8, receive[i]);
                DEBUG_PRINT(L_DEBUG, fp, "Warning message : %s\n\n", warning);

                i += receive[i] + U8;
                free(warning);
                break;
            }

            default:
                i += U8;
                i += receive[i] + U8;
                DEBUG_PRINT(L_DEBUG, fp, "TLV type unrecognised.\n");
                unsigned char *my_warning = build_warning("TLV not recognised, going to the next one.\n");
                unsigned char *datagram = build_header();

                add_tlv(datagram, my_warning);
                send_datagram(sock, saddr, datagram);
                break;
            }
        }
    }
    else
    {
        /* We got a bad header for the packet received, we send an appropriate warning.*/
        DEBUG_PRINT(L_DEBUG, fp, "Packet ignored, header incorrect\n\n");
        unsigned char *my_warning = build_warning("Packet ignored, header incorrect\n");
        unsigned char *datagram = build_header();

        add_tlv(datagram, my_warning);
        send_datagram(sock, saddr, datagram);
        return;
    }
}