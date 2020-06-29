#include "list.h"

int get_randint(int a, int b)
{
    srand(time(NULL));
    return rand() % (b - a) + a;
}

neighbour_list *init_neighbour_list(void)
{
    neighbour_list *new = malloc(sizeof(neighbour_list));
    if (new)
    {
        new->length = 0;
        new->head = NULL;
        new->tail = NULL;
    }
    else
    {
        DEBUG_PRINT(L_ERROR, fp, "Malloc failed init neighbour list !\n");
        exit(EXIT_FAILURE);
    }
    return new;
}

neighbour *get_neighbour_from_index(neighbour_list *target, int i)
{
    if (target)
    {
        if (i < target->length)
        {
            int j = 0;
            neighbour_node *tmp = target->head;

            while (i != j)
            {
                tmp = tmp->next;
                j++;
            }

            return tmp->current;
        }
        else
        {
            DEBUG_PRINT(L_DEBUG, fp, "Our list is too short, select a number from 1 to %d \n\n", target->length);
            return NULL;
        }
    }
    return NULL;
}

bool contain_neighbour(neighbour_list *target, struct sockaddr_in6 *addr)
{
    if (target)
    {
        neighbour_node *n = target->head;

        while (n)
        {
            if (compare_ip_adress(&n->current->adress.sin6_addr, &addr->sin6_addr))
            {
                return true;
            }
            n = n->next;
        }
    }
    return false;
}

bool compare_ip_adress(struct in6_addr *ip1, struct in6_addr *ip2)
{
    unsigned char current_ip[16];
    memset(current_ip, 0, 16);
    memcpy(current_ip, ip1, 16);
    unsigned char other_ip[16];
    memset(other_ip, 0, 16);
    memcpy(other_ip, ip2, 16);
    for (int i = 0; i < 16; i++)
    {
        if (current_ip[i] != other_ip[i])
        {
            return false;
        }
    }
    return true;
}

neighbour *get_neighbour(neighbour_list *target, struct sockaddr_in6 *addr)
{
    if (target)
    {
        neighbour_node *n = target->head;

        while (n)
        {
            if (compare_ip_adress(&n->current->adress.sin6_addr, &addr->sin6_addr))
            {
                return n->current;
            }
            n = n->next;
        }
    }
    return NULL;
}

neighbour *random_neighbour(neighbour_list *target)
{
    int random = get_randint(0, target->length);
    int i = 0;

    neighbour_node *tmp = target->head;
    while (i != random)
    {
        tmp = tmp->next;
        i++;
    }

    return tmp->current;
}

neighbour_list *append_neighbour_list(neighbour_list *target, neighbour *c)
{

    if (target)
    {

        neighbour_node *new = malloc(sizeof(neighbour_node));

        if (new)
        {

            new->current = c;
            new->next = NULL;

            if (!(target->tail))
            {

                new->prev = NULL;
                target->head = new;
                target->tail = new;
            }
            else
            {

                target->tail->next = new;
                new->prev = target->tail;
                target->tail = new;
            }

            target->length++;
        }
        else
        {
            DEBUG_PRINT(L_ERROR, fp, "Malloc failed !\n");
            exit(EXIT_FAILURE);
        }
    }

    return target;
}

void destroy_neighbour_list(neighbour_list *list)
{
    if (list)
    {

        neighbour_node *tmp = list->head;

        while (tmp)
        {

            neighbour_node *del = tmp;
            tmp = tmp->next;
            free(del->current);
            free(del);
        }

        free(list), list = NULL;
    }
}

void print_neighbour_list(neighbour_list *list)
{

    if (list)
    {
        int nbr = 0;
        neighbour_node *n = list->head;
        printf("                    ---------------------------------------------\n");
        printf("                    -           HERE IS OUR NEIGHBOUR LIST      -\n");
        printf("                    ---------------------------------------------\n\n");
        while (n)
        {
            printf("%d ----- ", nbr);
            unsigned char ip_neighbour[16];
            memset(ip_neighbour, 0, 16);
            memcpy(ip_neighbour, &n->current->adress.sin6_addr, 16);
            printf("Ip adress : ");
            for (int i = 0; i < 16; i++)
            {
                printf("%x ", ip_neighbour[i]);
            }
            printf(" ----- ");
            uint16_t port;
            memcpy(&port, &n->current->adress.sin6_port, 2);
            printf("Port : %d ----- ", ntohs(port));
            printf(" Last packet : %s", ctime(&n->current->last_packet_date));
            printf(" ----- Status : ");
            if (n->current->permanent)
            {
                printf("Permanent\n");
            }
            else
            {
                printf("Not permanent\n");
            }
            n = n->next;
            nbr++;
        }
        printf("\n");
    }
}

neighbour_list *neighbnour_list_remove(neighbour_list *list, struct sockaddr_in6 *addr)
{
    if (list)
    {

        neighbour_node *tmp = list->head;
        int found = 0;

        while (tmp && !found)
        {
            if (compare_ip_adress(&tmp->current->adress.sin6_addr, &addr->sin6_addr))
            {

                if (!(tmp->next) && !(tmp->prev))
                {

                    list->tail = NULL;
                    list->head = NULL;
                }
                else if (!(tmp->next))
                {

                    list->tail = tmp->prev;
                    list->tail->next = NULL;
                }
                else if (!(tmp->prev))
                {

                    list->head = tmp->next;
                    list->head->prev = NULL;
                }
                else
                {

                    tmp->next->prev = tmp->prev;
                    tmp->prev->next = tmp->next;
                }

                free(tmp->current);
                free(tmp);
                list->length--;
                found = 1;
            }
            else
            {

                tmp = tmp->next;
            }
        }
    }

    return list;
}

neighbour_list *neighbour_list_remove_all(neighbour_list *list, struct sockaddr_in6 *addr)
{
    if (list)
    {

        neighbour_node *tmp = list->head;
        while (tmp)
        {
            if (compare_ip_adress(&tmp->current->adress.sin6_addr, &addr->sin6_addr))
            {

                neighbour_node *del = tmp;
                tmp = tmp->next;

                if (!(del->next) && !(del->prev))
                {

                    list->tail = NULL;
                    list->head = NULL;
                }
                else if (!(del->next))
                {

                    list->tail = del->prev;
                    list->tail->next = NULL;
                }
                else if (!(del->prev))
                {

                    list->head = del->next;
                    list->head->prev = NULL;
                }
                else
                {

                    del->next->prev = del->prev;
                    del->prev->next = del->next;
                }
                free(del->current);
                free(del);
                list->length--;
            }
            else
            {
                tmp = tmp->next;
            }
        }
    }
    return list;
}

data_list *init_data_list(void)
{
    data_list *new = malloc(sizeof(data_list));
    if (new)
    {
        new->length = 0;
        new->head = NULL;
        new->tail = NULL;
    }
    else
    {
        DEBUG_PRINT(L_ERROR, fp, "Malloc failed !\n");
        exit(EXIT_FAILURE);
    }
    return new;
}

data_list *append_data_list(data_list *target, data *d)
{
    if (target)
    {

        data_node *new = malloc(sizeof(data_node));
        if (new)
        {

            new->current = d;
            new->next = NULL;

            if (!(target->tail))
            {

                new->prev = NULL;
                target->head = new;
                target->tail = new;
            }
            else
            {
                target->tail->next = new;
                new->prev = target->tail;
                target->tail = new;
            }

            target->length++;
        }
        else
        {
            DEBUG_PRINT(L_ERROR, fp, "Malloc failed !\n");
            exit(EXIT_FAILURE);
        }
    }

    return target;
}

data_list *append_data_list_sort(data_list *target, data *d)
{
    if (target)
    {

        data_node *new = malloc(sizeof(data_node));
        data_node *tmp;
        if (new)
        {

            new->current = d;
            new->next = NULL;

            if (!(target->tail))
            {

                new->prev = NULL;
                target->head = new;
                target->tail = new;
            }
            else if (memcmp(target->head->current->node_id, new->current->node_id, 8) >= 0)
            {
                new->next = target->head;
                new->prev = NULL;
                target->head = new;
            }
            else
            {
                tmp = target->head;
                while (tmp->next && memcmp(tmp->next->current->node_id, new->current->node_id, 8) < 0)
                {
                    tmp = tmp->next;
                }
                new->next = tmp->next;

                if (tmp->next)
                {
                    //new->next->prev = new;
                }
                tmp->next = new;
                new->prev = tmp;
            }

            target->length++;
        }
        else
        {
            DEBUG_PRINT(L_ERROR, fp, "Malloc failed !\n");
            exit(EXIT_FAILURE);
        }
    }

    return target;
}

data *get_node_data(data_list *target, unsigned char *node_id)
{
    if (target)
    {
        data_node *d = target->head;

        while (d)
        {
            if (memcmp(d->current->node_id, node_id, 8) == 0)
            {
                return d->current;
            }
            d = d->next;
        }
    }
    return NULL;
}

void destroy_data_list(data_list *list)
{
    if (list)
    {

        data_node *tmp = list->head;

        while (tmp)
        {

            data_node *del = tmp;
            tmp = tmp->next;
            free(del);
        }

        free(list), list = NULL;
    }
}

void print_data_list(data_list *list)
{
    data_node *d = list->head;
    int nbr = 0;
    printf("                    ---------------------------------------------\n");
    printf("                    -           HERE IS OUR DATA LIST           -\n");
    printf("                    ---------------------------------------------\n\n");
    while (d)
    {
        printf("%d --", nbr);
        printf("%.19s ---- ", ctime(&d->current->last_update));
        unsigned char id[8];
        memset(id, 0, 8);
        memcpy(id, &d->current->node_id, 8);
        printf(" Node id : ");
        for (int i = 0; i < 8; i++)
        {
            printf("%x ", id[i]);
        }
        printf(" ----- ");
        printf(" Seqno : %d ", ntohs(d->current->seqno));
        printf("------ ");
        printf(" Data : %s ", d->current->msg);
        printf("\n\n");
        d = d->next;
        nbr++;
    }
}

data_list *data_list_remove(data_list *list, unsigned char *node_id)
{
    if (list)
    {

        data_node *tmp = list->head;
        int found = 0;

        while (tmp && !found)
        {
            if (memcmp(tmp->current->node_id, node_id, 8) == 0)
            {

                if (!(tmp->next) && !(tmp->prev))
                {

                    list->tail = NULL;
                    list->head = NULL;
                }
                else if (!(tmp->next))
                {

                    list->tail = tmp->prev;
                    list->tail->next = NULL;
                }
                else if (!(tmp->prev))
                {

                    list->head = tmp->next;
                    list->head->prev = NULL;
                }
                else
                {
                    tmp->next->prev = tmp->prev;
                    tmp->prev->next = tmp->next;
                }

                free(tmp);
                list->length--;
                found = 1;
            }
            else
            {

                tmp = tmp->next;
            }
        }
    }
    return list;
}

data_list *data_list_remove_all(data_list *list, unsigned char *node_id)
{
    if (list)
    {

        data_node *tmp = list->head;
        while (tmp)
        {
            if (memcmp(tmp->current->node_id, node_id, 8) == 0)
            {

                data_node *del = tmp;
                tmp = tmp->next;

                if (!(del->next) && !(del->prev))
                {

                    list->tail = NULL;
                    list->head = NULL;
                }
                else if (!(del->next))
                {

                    list->tail = del->prev;
                    list->tail->next = NULL;
                }
                else if (!(del->prev))
                {

                    list->head = del->next;
                    list->head->prev = NULL;
                }
                else
                {

                    del->next->prev = del->prev;
                    del->prev->next = del->next;
                }
                free(del);
                list->length--;
            }
            else
            {
                tmp = tmp->next;
            }
        }
    }
    return list;
}

void bubble_sort_data_bytime(data_list *target)
{
    int swapped;
    data_node *tmp;
    data_node *tmp2 = NULL;

    if (target->head == NULL)
        return;
    do
    {
        swapped = 0;
        tmp = target->head;

        while (tmp->next != tmp2)
        {
            if (difftime(tmp->current->last_update, tmp->next->current->last_update) < 0)
            {
                data *data = tmp->current;
                tmp->current = tmp->next->current;
                tmp->next->current = data;
                swapped = 1;
            }
            tmp = tmp->next;
        }
        tmp = tmp2;
    } while (swapped);
}