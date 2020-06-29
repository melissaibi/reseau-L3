#include "main.h"

/* Getting adress for hostname and port given.*/
void get_server_address(char *hostname, char *port, struct sockaddr_in6 *saddr)
{
  struct addrinfo *p;
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_V4MAPPED | AI_ALL;
  hints.ai_protocol = 17;

  int sock = 0;

  int rc = getaddrinfo(hostname, port, &hints, &p);

  if (rc < 0)
  {
    DEBUG_PRINT(L_ERROR, fp, "Getaddrinfo error\n");
    exit(EXIT_FAILURE);
  }

  while (p != NULL)
  {

    /* We try to send a packet of 1 octet to the adresses.*/

    *saddr = *(struct sockaddr_in6 *)(p->ai_addr);
    unsigned char toto[1];
    toto[0] = 'a';
    sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);

    int send = sendto(sock, toto, 1, 0, (struct sockaddr *)saddr, sizeof(*saddr));

    /* Sento don't succeed, we go to the next adress.*/
    if (send < 0)
    {
      DEBUG_PRINT(L_ERROR, fp, "Send fail to : \n");
      unsigned char ip_adress[16];
      memcpy(ip_adress, &saddr->sin6_addr, 16);

      for (int i = 0; i < 16; i++)
      {
        DEBUG_PRINT(L_DEBUG, fp, "%x ", ip_adress[i]);
      }
      p = p->ai_next;
    }
    else
    {
      /* Sendto succeeded, we got our adress stored in saddr given as parameter.*/

      DEBUG_PRINT(L_DEBUG, fp, "\nSend achieved to an adress.\n");
      break;
    }
  }

  DEBUG_PRINT(L_DEBUG, fp, "\n\n");
  DEBUG_PRINT(L_DEBUG, fp, "Final ip adress chosen : ");

  unsigned char ip_adress_final[16];
  memcpy(ip_adress_final, &saddr->sin6_addr, 16);

  for (int i = 0; i < 16; i++)
  {
    DEBUG_PRINT(L_DEBUG, fp, "%x ", ip_adress_final[i]);
  }

  DEBUG_PRINT(L_DEBUG, fp, "\n");
  freeaddrinfo(p);
  close(sock);
  /* Close socket.*/
}

/* Server.*/
void serveur(int sock_send, struct sockaddr_in6 saddr, neighbour_list *neighbour_l, data_list *data_l)
{
  socklen_t addr_length = sizeof(saddr);
  unsigned char packet_received[MAXLINE];
  memset(packet_received, 0, MAXLINE);

  while (!(pthread_server_exit))
  {
    DEBUG_PRINT(L_DEBUG, fp, "Entering in recvfrom while \n\n");
    DEBUG_PRINT(L_DEBUG, fp, "Waiting to receive a packet...\n\n");

    int r = recvfrom(sock_send, packet_received, MAXLINE, 0, (struct sockaddr *)&saddr, &addr_length);

    if (r < 0)
    {
      DEBUG_PRINT(L_ERROR, fp, "recvfrom error.\n");
      continue;
    }

    DEBUG_PRINT(L_TRACE, fp, "Description of the packet : \n");
    uint16_t packet_length;
    memcpy(&packet_length, packet_received + 2 * U8, U16);

    DEBUG_PRINT(L_TRACE, fp, "Packet size is : %d\n", ntohs(packet_length));
    DEBUG_PRINT(L_TRACE, fp, "The packet itself in hexa : ");
    for (int i = 0; i < ntohs(packet_length) + 2 * U8 + U16; i++)
    {
      DEBUG_PRINT(L_TRACE, fp, "%x ", packet_received[i]);
    }

    parse_packet(data_l, neighbour_l, packet_received, &saddr, sock_send);
  }
}

static void *fn_serveur(void *p_data)
{
  serveur(sock_send, saddr, neighbour_l, data_l);
  pthread_exit(NULL);
  return NULL;
}

static void *fn_innondation(void *p_data)
{
  inondation_process(neighbour_l, data_l, sock_send);
  pthread_exit(NULL);
  return NULL;
}

/* Linux get_mac_adress method.*/
#if defined(SIOCGIFHWADDR)
void get_mac_adress(unsigned char *mac_adress)
{
  struct ifreq ifr;
  struct ifconf ifc;
  char buf[1024];
  int success = 0;

  int sock = socket(AF_INET6, SOCK_DGRAM, 0);
  if (sock == -1)
  {
    DEBUG_PRINT(L_ERROR, fp, "socket error (in mac_adress)");
  }

  ifc.ifc_len = sizeof(buf);
  ifc.ifc_buf = buf;
  if (ioctl(sock, SIOCGIFCONF, &ifc) == -1)
  {
    DEBUG_PRINT(L_ERROR, fp, "first ioct error (in mac_adress).");
  }

  struct ifreq *it = ifc.ifc_req;
  const struct ifreq *const end = it + (ifc.ifc_len / sizeof(struct ifreq));
  for (; it != end; ++it)
  {
    strcpy(ifr.ifr_name, it->ifr_name);

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0)
    {
      if (!(ifr.ifr_flags & IFF_LOOPBACK))
      { /* don't count loopback. */
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0)
        {
          success = 1;
          break;
        }
      }
    }
    else
    {
      DEBUG_PRINT(L_ERROR, fp, "second ioctl error (in mac_adress).");
    }
  }
  if (success)
    memcpy(mac_adress, ifr.ifr_hwaddr.sa_data, 6);
  close(sock);
}
/* BSD/OS-X get_mac_adress method.*/
#else
void get_mac_adress(unsigned char *mac_adress)
{
  struct ifaddrs *ifaddr = NULL;
  struct ifaddrs *ifa = NULL;

  if (getifaddrs(&ifaddr) == -1)
  {
    DEBUG_PRINT(L_ERROR, fp, "getifaddrs");
  }
  else
  {
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
      if ((ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_LINK) && strcmp(ifa->ifa_name, "en0") == 0)
      {
        struct sockaddr_dl *s = (struct sockaddr_dl *)ifa->ifa_addr;
        memcpy(mac_adress, s->sdl_data + 3, 8);
        return;
      }
    }
    freeifaddrs(ifaddr);
  }
}
#endif

int main(int argc, char *argv[])
{

  /* Taking host name destination port, and source port from main arguments.*/
  char *hostname;
  char *dst_port;
  char *src_port;
  if (argc == 5)
  {
    hostname = argv[1];
    dst_port = argv[2];
    src_port = argv[3];
    DEBUG = atoi(argv[4]);
  }
  else if (argc > 5)
  {
    printf("Too many arguments, five arguments needed.\n");
    fflush(stdout);
    exit(EXIT_FAILURE);
  }
  else
  {
    printf("Too few arguments, five arguments needed.\n");
    fflush(stdout);
    exit(EXIT_FAILURE);
  }

  /* Opening a debugging file to put in all fprintf() traces, help for debugging our server.*/
  fp = fopen("debug_serveur.txt", "w");
  if (fp == NULL)
  {
    DEBUG_PRINT(L_ERROR, fp, "Cannot create/open debug.txt file \n");
    exit(EXIT_FAILURE);
  }

  DEBUG_PRINT(L_DEBUG, fp, "Entering in the main\n\n");

  /* Initialising my_id from adress mac.*/
  memset(my_id, 0, 8);
  get_mac_adress(my_id);

  DEBUG_PRINT(L_DEBUG, fp, "MY ID : ");
  for (int z = 0; z < 8; z++)
  {
    DEBUG_PRINT(L_DEBUG, fp, "%x ", my_id[z]);
  }
  DEBUG_PRINT(L_DEBUG, fp, ".\n\n");

  /* Creating the socket for the whole program, to send and listen with wanted options via setsockopt().*/
  sock_send = socket(AF_INET6, SOCK_DGRAM, 0);

  if (sock_send < 0)
  {
    DEBUG_PRINT(L_ERROR, fp, "error when creating socket");
    exit(EXIT_FAILURE);
  }

  int val_send = 0;

  int s_send = setsockopt(sock_send, IPPROTO_IPV6, IPV6_V6ONLY, &val_send, sizeof(val_send));
  if (s_send < 0)
  {
    DEBUG_PRINT(L_ERROR, fp, "error in set sock option");
    exit(EXIT_FAILURE);
  }

  memset(&saddr, 0, sizeof(saddr));

  /* Getting serveur adress and store it to saddr global variable.*/
  get_server_address(hostname, dst_port, &saddr);

  /* Initialising both neighbour and data list.*/
  neighbour_l = init_neighbour_list();
  data_l = init_data_list();

  /* Adding source adress as permanent neighbour.*/
  neighbour *teacher = malloc(sizeof(neighbour));
  teacher->adress = saddr;
  teacher->permanent = true;
  teacher->last_packet_date = time(0);

  append_neighbour_list(neighbour_l, teacher);

  /* Adding my data to my data list.*/
  data *d = malloc(sizeof(data));
  memcpy(d->node_id, my_id, 8);
  d->seqno = 0;
  d->msg_length = strlen("Begining");
  memset(d->msg, 0, 192);
  memcpy(d->msg, "Begining", d->msg_length);
  d->last_update = time(0);
  hash_node_data(d);

  append_data_list_sort(data_l, d);

  /* Creating a random adress with wanted port.*/
  struct sockaddr_in6 my_adress;
  memset(&my_adress, 0, sizeof(my_adress));
  my_adress.sin6_family = AF_INET6;
  my_adress.sin6_addr = in6addr_any;
  my_adress.sin6_port = htons(atoi(src_port));

  /* Binding the socket to the wanted port.*/
  if (bind(sock_send, (struct sockaddr *)&my_adress, sizeof(my_adress)) < 0)
  {
    DEBUG_PRINT(L_ERROR, fp, "Bind sock_send error.\n");
  }

  /* Initialisation of mutex neighbour. */
  if (pthread_mutex_init(&mutex_neighbour, NULL) != 0)
  {
    DEBUG_PRINT(L_ERROR, fp, "Mutex init has failed for neighbour.\n");
    exit(EXIT_FAILURE);
  }

  /* Initialisation of mutex data. */
  if (pthread_mutex_init(&mutex_data, NULL) != 0)
  {
    DEBUG_PRINT(L_ERROR, fp, "Mutex init has failed for data.\n");
    exit(EXIT_FAILURE);
  }

  int ret = 0;
  pthread_t thread_serveur;

  /* Creation of thread serveur. */
  ret = pthread_create(&thread_serveur, NULL, fn_serveur, NULL);
  if (ret != 0)
  {
    DEBUG_PRINT(L_ERROR, fp, "Failed to create thread serveur.\n");
    exit(EXIT_FAILURE);
  }

  pthread_t thread_innondation;

  /* Creation of thread innondation. */
  ret = pthread_create(&thread_innondation, NULL, fn_innondation, NULL);
  if (ret != 0)
  {
    DEBUG_PRINT(L_ERROR, fp, "Failed to create thread innondation.\n");
    exit(EXIT_FAILURE);
  }

  /* User interface. */
  user_interface(neighbour_l, data_l);

  printf("User interface done, waiting for server and innondation to end !\n");
  fflush(stdout);
  pthread_server_exit = true;
  pthread_innondation_exit = true;

  /* Wait for another thread to end. */
  pthread_join(thread_serveur, NULL);

  printf("Server has joined !\n");
  fflush(stdout);

  /* Wait for another thread to end. */
  pthread_join(thread_innondation, NULL);

  printf("Innondation has joined !\n");
  fflush(stdout);

  /* If we are there, that worked, we close everything.*/
  pthread_mutex_destroy(&mutex_neighbour);
  pthread_mutex_destroy(&mutex_data);
  destroy_data_list(data_l);
  destroy_neighbour_list(neighbour_l);
  fclose(fp);
  fclose(fp1);
  close(sock_send);
  printf("Goodbye!");
  fflush(stdout);
}
