#include "interface.h"

void manual()
{
    printf("\n");
    printf(CO "****************************************** WELCOME TO THE USER TERMINAL INTERFACE  ******************************************\n\n\n\n" COO);
    printf("             	              	* HERE IS THE MANUAL DESCRIBING WHAT YOU CAN DO * \n\n\n\n");
    printf("The following options are available : \n\n");
    printf("-man            Display the manual.\n\n");
    printf("-ne             Display the neighbour list with relative informations.\n\n");
    printf("-da             Display the data list with relative informations.\n\n");
    printf("-new            Publish a new data.\n\n");
    printf("-clear          To clear the user interface.\n\n");
    printf("-exit           To get out of the whole program.\n\n");
}

void user_interface(neighbour_list *neighbour_l, data_list *data_l)
{
    manual();
    while (1)
    {
        char buff[100];
        fgets(buff, sizeof buff, stdin);
        if (strcmp(buff, "man\n") == 0)
        {
            manual();
        }
        else if (strcmp(buff, "ne\n") == 0)
        {
            pthread_mutex_lock(&mutex_neighbour);
            print_neighbour_list(neighbour_l);
            printf("\n\n");
            pthread_mutex_unlock(&mutex_neighbour);
        }
        else if (strcmp(buff, "da\n") == 0)
        {
            pthread_mutex_lock(&mutex_data);
            print_data_list(data_l);
            printf("\n\n");
            pthread_mutex_unlock(&mutex_data);
        }
        else if (strcmp(buff, "new\n") == 0)
        {
            printf("Type the data you want to add : \n\n");
            char buff_node_state[192];
            fgets(buff_node_state, sizeof buff_node_state, stdin);
            pthread_mutex_lock(&mutex_data);

            data *d = get_node_data(data_l, my_id);
            d->msg_length = strlen(buff_node_state);

            memset(d->msg, 0, 192);
            memcpy(d->msg, buff_node_state, strlen(buff_node_state));
            d->seqno = htons((ntohs(d->seqno) + 1) % 65536);
            d->last_update = time(0);
            hash_node_data(d);
            pthread_mutex_unlock(&mutex_data);

            printf(CO "New data added\n\n" COO);
        }
        else if (strcmp(buff, "exit\n") == 0)
        {
            return;
        }
        else if (strcmp(buff, "clear\n") == 0)
        {
            system("@cls||clear");
        }
        else
        {
            printf(CO "Unavailable command.\n" COO);
        }
    }
}

void skip_input(FILE *stream)
{
    int c;
    do
    {
        c = fgetc(stream);
    } while (c != EOF && c != '\n');
}

void packet_process()
{
    printf("- WELCOME TO THE SENDING PACKET PROCESS -\n\n");
    printf(" - Just select a tlv number to add to the current packet, from 0 to 9 -\n\n");
    printf("Once you're done just type send to send the packet and exit to come back to the user interface.\n\n");
    printf("You will choose when you are done, the neighbour where you want your packet to go to.\n\n");
}

void user_interface_debug(neighbour_list *neighbour_l, data_list *data_l, int sock)
{
    printf("WELCOME TO OUR USER INTERFACE TYPE man to begin \n\n");
    while (1)
    {
        char buff[100];
        fgets(buff, sizeof buff, stdin);
        if (strcmp(buff, "man\n") == 0)
        {
            manual();
        }
        else if (strcmp(buff, "ne\n") == 0)
        {
            print_neighbour_list(neighbour_l);
        }
        else if (strcmp(buff, "da\n") == 0)
        {
            print_data_list(data_l);
        }
        else if (strcmp(buff, "pa\n") == 0)
        {
            packet_process();

            unsigned char *datagram = build_header();
            uint16_t bodylength;
            memcpy(&bodylength, datagram + 2 * U8, U16);
            bodylength = ntohs(bodylength);

            while (bodylength + 4 <= MAXLINE)
            {
                printf("Actual size of your packet : %d\n\n", bodylength + 4);
                printf("Select your tlv number or type send\n\n");
                char buff_packet[100];
                memset(buff_packet, 0, 100);
                fgets(buff_packet, sizeof buff_packet, stdin);
                if (strcmp(buff_packet, "0\n") == 0)
                {
                    unsigned char *pad1 = build_pad1();
                    add_tlv(datagram, pad1);
                    printf("Tlv pad1 added to datagram\n\n");
                }
                else if (strcmp(buff_packet, "1\n") == 0)
                {
                    /*
          unsigned char *padN = build_padN(atoi(buff_padN));
          add_tlv(datagram, padN);
          printf("Tlv padN request added to datagram\n\n");
          */
                }
                else if (strcmp(buff_packet, "2\n") == 0)
                {
                    unsigned char *neighbour_req = build_neighbour_req();
                    add_tlv(datagram, neighbour_req);
                    printf("Tlv neighbour request added to datagram\n\n");
                }
                else if (strcmp(buff_packet, "3\n") == 0)
                {
                    neighbour *n = random_neighbour(neighbour_l);
                    unsigned char ip_adress[16];
                    memcpy(ip_adress, &n->adress.sin6_addr, 16);
                    unsigned char *neighbour = build_neighbour(ip_adress, n->adress.sin6_port);
                    add_tlv(datagram, neighbour);
                    printf("Random tlv neighbour added to datagram\n\n");
                }
                else if (strcmp(buff_packet, "4\n") == 0)
                {
                    unsigned char my_network_hash[16];
                    calculate_network_hash(data_l, my_network_hash);
                    unsigned char *tlv_network_hash = build_network_hash(my_network_hash);
                    add_tlv(datagram, tlv_network_hash);
                    printf("Tlv network hash added to datagram\n\n");
                }
                else if (strcmp(buff_packet, "5\n") == 0)
                {
                    unsigned char *net_state_req = build_network_state_req();
                    add_tlv(datagram, net_state_req);
                    printf("Tlv network state request added to datagram\n\n");
                }
                else if (strcmp(buff_packet, "6\n") == 0)
                {
                    unsigned char *node_hash = build_node_hash(data_l->head->current);
                    add_tlv(datagram, node_hash);
                    printf("Tlv node hash added to datagram\n\n");
                }
                else if (strcmp(buff_packet, "7\n") == 0)
                {
                    unsigned char *node_state_req = build_node_state_request(my_id);
                    add_tlv(datagram, node_state_req);
                    printf("Tlv node state request added to datagram\n\n");
                }
                else if (strcmp(buff_packet, "8\n") == 0)
                {
                    printf("Type the data you want to add to your node state : \n\n");
                    char buff_node_state[192];
                    fgets(buff_node_state, sizeof buff_node_state, stdin);

                    data *d = get_node_data(data_l, my_id);
                    d->msg_length = strlen(buff_node_state);
                    memcpy(d->msg, buff_node_state, strlen(buff_node_state));
                    d->seqno = (d->seqno + 1) % 65536;
                    hash_node_data(d);

                    unsigned char *node_state = build_node_state(d);
                    add_tlv(datagram, node_state);
                    printf("Tlv node state added to datagram\n\n");
                }
                else if (strcmp(buff_packet, "9\n") == 0)
                {
                    printf("Type the data you want to add to your warning : \n\n");
                    char buff_warning[192];
                    fgets(buff_warning, sizeof buff_warning, stdin);
                    unsigned char *warning = build_warning(buff_warning);
                    add_tlv(datagram, warning);
                    printf("Tlv warning added to datagram\n\n");
                }
                else if (strcmp(buff_packet, "exit\n") == 0)
                {
                    free(datagram);
                    break;
                }
                else if (strcmp(buff_packet, "send\n") == 0)
                {

                    while (1)
                    {
                        printf("Select by digit which neighbour will be the receiver of the packet\n\n");
                        print_neighbour_list(neighbour_l);
                        int r, a;
                        r = scanf("%d", &a);
                        if (r == EOF)
                            break;
                        if (r != 1)
                        {
                            printf("Number must be numeric!\n");
                            skip_input(stdin);
                        }
                        else if (a < 0)
                        {
                            printf("Number must be postive\n");
                            skip_input(stdin);
                        }
                        else
                        {
                            neighbour *nei = get_neighbour_from_index(neighbour_l, a);
                            if (nei)
                            {
                                printf("Neighbour %d selected as receiver \n\n", a);
                                send_datagram(sock, &nei->adress, datagram);
                                printf("Datagram well sent\n\n");
                                break;
                            }
                            else
                            {
                                continue;
                            }
                        }
                    }
                    break;
                }
                else
                {
                    free(datagram);
                    printf("Impossible action please read the manual\n\n!");
                    break;
                }
                memcpy(&bodylength, datagram + 2 * U8, U16);
                bodylength = ntohs(bodylength);
            }
            free(datagram);
            printf("Your packet size is over 1024octets, going back\n\n");
            printf("Welcome back \n\n");
            manual();
        }
    }
}