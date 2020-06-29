#include "client.h"

const uint8_t magic = 95;
const uint8_t version = 1;
FILE *fp1;

unsigned char *get_random_dev()
{
    unsigned char *buff = malloc(8);
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
    {
        DEBUG_PRINT(L_ERROR, fp, "Cannot open dev/urandom file.\n");
    }
    int rc = read(fd, buff, 8);
    if (rc < 0)
    {
        DEBUG_PRINT(L_ERROR, fp, "Can't write in dev/urandom file.\n");
    }
    close(fd);
    return buff;
}

unsigned char *build_header()
{
    uint16_t bodylength = 0;
    unsigned char *head = malloc(MAXLINE);
    memset(head, 0, MAXLINE);
    memcpy(head, &magic, U8);
    memcpy(head + U8, &version, U8);
    memcpy(head + 2 * U8, &bodylength, U16);
    return head;
}

unsigned char *build_pad1()
{
    unsigned char *pad1 = malloc(U8);
    memset(pad1, 0, U8);
    uint8_t type = 0;
    memcpy(pad1, &type, U8);
    return pad1;
}

unsigned char *build_padN(uint8_t length)
{
    unsigned char *padN = malloc(2 * U8 + length);
    memset(padN, 0, 2 * U8 + length);
    uint8_t type = 1;
    memcpy(padN, &type, U8);
    memcpy(padN + U8, &length, U8);
    memset(padN + 2 * U8, 0, length);
    return padN;
}

unsigned char *build_neighbour_req()
{
    unsigned char *neighbour_req = malloc(2 * U8);
    memset(neighbour_req, 0, 2 * U8);
    uint8_t type = 2;
    uint8_t bodylength = 0;
    memcpy(neighbour_req, &type, U8);
    memcpy(neighbour_req + U8, &bodylength, U8);
    return neighbour_req;
}

unsigned char *build_neighbour(unsigned char *ip, uint16_t port)
{
    unsigned char *neighbour = malloc(2 * UU64 + U16);
    memset(neighbour, 0, 2 * U8 + 2 * UU64);
    uint8_t type = 3;
    uint8_t length = 2 * UU64 + U16;
    memcpy(neighbour, &type, U8);
    memcpy(neighbour + U8, &length, U8);
    memcpy(neighbour + 2 * U8, ip, 2 * UU64);
    memcpy(neighbour + 2 * U8 + 2 * UU64, &port, U16);
    return neighbour;
}

void calculate_network_hash(data_list *list, unsigned char *hash)
{
    unsigned char *hash_buffer = malloc(16 * list->length);
    int size = 0;
    if (list)
    {
        data_node *tmp = list->head;
        while (tmp)
        {
            memcpy(hash_buffer + size, tmp->current->hash, 16);
            size += 16;
            tmp = tmp->next;
        }
    }
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    unsigned char hash_tmp[32];
    SHA256_Update(&ctx, hash_buffer, 16 * list->length);
    SHA256_Final(hash_tmp, &ctx);
    free(hash_buffer);
    memcpy(hash, hash_tmp, 16);
}

unsigned char *build_network_hash(unsigned char *network_hash)
{
    unsigned char *net_hash = malloc(2 * U8 + 16);
    memset(net_hash, 0, 2 * U8 + 16);
    uint8_t type = 4;
    uint8_t length = 16;
    memcpy(net_hash, &type, U8);
    memcpy(net_hash + U8, &length, U8);
    memcpy(net_hash + 2 * U8, network_hash, 16);
    return net_hash;
}

unsigned char *build_network_state_req()
{
    unsigned char *net_state_req = malloc(2 * U8);
    memset(net_state_req, 0, 2 * U8);
    uint8_t type = 5;
    uint8_t bodylength = 0;
    memcpy(net_state_req, &type, U8);
    memcpy(net_state_req + U8, &bodylength, U8);
    return net_state_req;
}

unsigned char *build_node_hash(data *d)
{
    unsigned char *node_hash = malloc(2 * U8 + 8 + U16 + 16);
    memset(node_hash, 0, 2 * U8 + 8 + U16 + 16);
    uint8_t type = 6;
    uint8_t bodylength = 8 + U16 + 16;
    memcpy(node_hash, &type, U8);
    memcpy(node_hash + U8, &bodylength, U8);
    memcpy(node_hash + 2 * U8, &d->node_id, 8);
    memcpy(node_hash + 2 * U8 + 8, &d->seqno, U16);
    memcpy(node_hash + 2 * U8 + 8 + U16, &d->hash, 16);
    return node_hash;
}

unsigned char *build_node_state_request(unsigned char *id)
{
    unsigned char *node_state_req = malloc(2 * U8 + UU64);
    memset(node_state_req, 0, 2 * U8 + UU64);
    uint8_t type = 7;
    uint8_t bodylength = 8;
    memcpy(node_state_req, &type, U8);
    memcpy(node_state_req + U8, &bodylength, U8);
    memcpy(node_state_req + 2 * U8, id, 8);
    return node_state_req;
}

void hash_node_data(data *d)
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    uint8_t size_data_to_hash = U16 + UU64 + d->msg_length;
    char data_to_hash[size_data_to_hash];
    memcpy(data_to_hash, &d->node_id, UU64);
    memcpy(data_to_hash + UU64, &d->seqno, U16);
    memcpy(data_to_hash + UU64 + U16, d->msg, d->msg_length);
    SHA256_Update(&ctx, data_to_hash, size_data_to_hash);
    unsigned char tmp[32];
    SHA256_Final(tmp, &ctx);
    memcpy(d->hash, tmp, 16);
}

void hash_data(data *d, unsigned char *hash)
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    unsigned char tmp[32];
    uint8_t size_data_to_hash = U16 + UU64 + d->msg_length;
    char data_to_hash[size_data_to_hash];
    memcpy(data_to_hash, &d->node_id, UU64);
    memcpy(data_to_hash + UU64, &d->seqno, U16);
    memcpy(data_to_hash + UU64 + U16, d->msg, d->msg_length);
    SHA256_Update(&ctx, data_to_hash, size_data_to_hash);
    SHA256_Final(tmp, &ctx);
    memcpy(hash, tmp, 16);
}

unsigned char *build_node_state(data *d)
{
    unsigned char *node_state = malloc(2 * U8 + UU64 + U16 + 2 * UU64 + d->msg_length);
    memset(node_state, 0, 2 * U8 + UU64 + U16 + 2 * UU64 + d->msg_length);
    uint8_t type = 8;
    uint8_t bodylength = UU64 + U16 + 2 * UU64 + d->msg_length;
    memcpy(node_state, &type, U8);
    memcpy(node_state + U8, &bodylength, U8);
    memcpy(node_state + 2 * U8, &d->node_id, UU64);
    memcpy(node_state + 2 * U8 + UU64, &d->seqno, U16);
    memcpy(node_state + 2 * U8 + UU64 + U16, d->hash, 2 * UU64);
    memcpy(node_state + 2 * U8 + UU64 + U16 + 2 * UU64, d->msg, d->msg_length);
    return node_state;
}

unsigned char *build_warning(char *msg)
{
    unsigned char *warning = malloc(2 * U8 + strlen(msg));
    memset(warning, 0, 2 * U8 + strlen(msg));
    uint8_t type = 9;
    uint8_t bodylength = strlen(msg);
    memcpy(warning, &type, U8);
    memcpy(warning + U8, &bodylength, U8);
    memcpy(warning + 2 * U8, msg, strlen(msg));
    return warning;
}

void send_datagram(int sock, struct sockaddr_in6 *saddr, unsigned char *datagram)
{
    uint16_t datagram_length;
    memcpy(&datagram_length, datagram + 2 * U8, U16);
    int r = sendto(sock, datagram, ntohs(datagram_length) + 2 * U8 + U16, 0, (struct sockaddr *)saddr,
                   sizeof(*saddr));

    DEBUG_PRINT(L_DEBUG, fp, "Datagram length : %lu.\n", ntohs(datagram_length) + 2 * U8 + U16);
    DEBUG_PRINT(L_DEBUG, fp, "Sendto result : %d.\n", r);
    if (r < 0)
    {
        DEBUG_PRINT(L_ERROR, fp, "Sendto error, maybe an IPV6 adress which is not supported on my system.");
    }
    else
    {
        DEBUG_PRINT(L_DEBUG, fp, "In send datagram method, datagram sent.\n");
    }
    free(datagram);
}

void add_tlv(unsigned char *header, unsigned char *tlv)
{
    if (header && tlv)
    {
        uint16_t body_length;
        memcpy(&body_length, header + 2 * U8, U16);
        body_length = ntohs(body_length);

        uint8_t tlv_length = tlv[1] + 2 * U8;
        memcpy(header + body_length + (2 * U8) + U16, tlv, tlv_length);
        body_length += tlv_length;
        body_length = htons(body_length);
        memcpy(header + 2 * U8, &body_length, U16);
        free(tlv);
    }
}

int packet_length(unsigned char *packet)
{
    uint16_t bodylength;
    memcpy(&bodylength, packet + 2 * U8, U16);
    return (ntohs(bodylength) + 2 * U8 + U16);
}

void inondation_process(neighbour_list *neighbour_l, data_list *data_l, int sock)
{
    /* Opening a file to write in debug informations relative to inondation.*/
    FILE *fp1;
    fp1 = fopen("debug_innondation.txt", "w");
    if (fp1 == NULL)
    {
        DEBUG_PRINT(L_ERROR, fp1, "Cannot create/open debug_innondation.txt file.\n");
        exit(EXIT_FAILURE);
    }

    while (!(pthread_innondation_exit))
    {
        if (neighbour_l)
        {

            neighbour_node *n = neighbour_l->head;

            while (n)
            {

                time_t now = time(0);

                pthread_mutex_lock(&mutex_neighbour);
                /* Remove neighbour from list if he is dead since 70 sec.*/
                if (difftime(now, n->current->last_packet_date) >= 70 && !(n->current->permanent))
                {
                    DEBUG_PRINT(L_DEBUG, fp1, "Neighbour deleted because no emission since 70sec.\n\n");
                    neighbnour_list_remove(neighbour_l, &n->current->adress);
                }
                pthread_mutex_unlock(&mutex_neighbour);

                /* Sending network hash to my neighbours.*/
                unsigned char my_network_hash[16];
                pthread_mutex_lock(&mutex_data);
                calculate_network_hash(data_l, my_network_hash);
                pthread_mutex_unlock(&mutex_data);

                DEBUG_PRINT(L_DEBUG, fp1, "Sending my network hash to all my neighbours.\n\n");

                DEBUG_PRINT(L_DEBUG, fp1, "My network hash : \n\n");
                for (int i = 0; i < 16; i++)
                {
                    DEBUG_PRINT(L_DEBUG, fp1, "%x ", my_network_hash[i]);
                }
                DEBUG_PRINT(L_DEBUG, fp1, ".\n\n");

                unsigned char ip_adress_neighbour[16];
                memcpy(ip_adress_neighbour, &n->current->adress.sin6_addr, 16);

                DEBUG_PRINT(L_DEBUG, fp1, "Network hash sent to ip : ");
                for (int i = 0; i < 16; i++)
                {
                    DEBUG_PRINT(L_DEBUG, fp1, "%x ", ip_adress_neighbour[i]);
                }
                DEBUG_PRINT(L_DEBUG, fp1, ".\n\n");

                unsigned char *tlv_network_hash = build_network_hash(my_network_hash);

                unsigned char *datagram = build_header();
                add_tlv(datagram, tlv_network_hash);
                send_datagram(sock, &n->current->adress, datagram);

                DEBUG_PRINT(L_DEBUG, fp1, "Network hash sent.\n\n");

                n = n->next;
            }

            /* Less than 5 entries in neighbour list, sending neighbour request to one of my neighbours.*/
            if (neighbour_l->length < 5)
            {

                DEBUG_PRINT(L_DEBUG, fp1, "I have less than 5 entries in neighbour list.\n\n");

                neighbour *random_neigh = random_neighbour(neighbour_l);
                unsigned char *datagram = build_header();
                unsigned char *neighbour_request = build_neighbour_req();

                add_tlv(datagram, neighbour_request);
                send_datagram(sock, &random_neigh->adress, datagram);

                DEBUG_PRINT(L_DEBUG, fp1, "Neighbour request sent to a random neighbour.\n\n");
            }
        }
        /* We wait 20sec until next innondation process.*/
        DEBUG_PRINT(L_DEBUG, fp1, "Innondation done, now we sleep for 20sec.\n\n");
        sleep(20);
    }
}