#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/time.h>

// ICMP packet size
#define PACKET_SIZE 64

// Validate IP address
int validateIpAddress(char *ipAddress) {
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
    return result != 0;
}

// Calculate ICMP checksum
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }

    if (len == 1) {
        sum += *(unsigned char *) buf;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;

    return result;
}

// Send ICMP packet
void sendPacket(int sockfd, struct sockaddr_in addr) {
    char packet[PACKET_SIZE];
    struct icmp *icmp_header = (struct icmp *) packet;

    // Set ICMP header fields
    icmp_header->icmp_type = ICMP_ECHO;
    icmp_header->icmp_code = 0;
    icmp_header->icmp_id = getpid() & 0xFFFF;
    icmp_header->icmp_seq = 0;
    icmp_header->icmp_cksum = 0;
    memset(packet + sizeof(struct icmp), 0, PACKET_SIZE - sizeof(struct icmp));
    icmp_header->icmp_cksum = checksum(packet, PACKET_SIZE);

    // Send ICMP packet
    int bytes_sent = sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr *) &addr, sizeof(addr));

    if (bytes_sent < 0) {
        printf("Error sending ICMP packet.\n");
        return;
    }
}

// Receive ICMP packet
int receivePacket(int sockfd, struct sockaddr_in addr, struct timeval tv) {
    char packet[PACKET_SIZE];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    int bytes_received = recvfrom(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr *) &from, &fromlen);

    if (bytes_received < 0) {
        printf("Error receiving ICMP packet.\n");
        return -1;
    }

    struct iphdr *ip_header = (struct iphdr *) packet;
    struct icmp *icmp_header = (struct icmp *) (packet + sizeof(struct iphdr));

    // Check if the ICMP packet is a reply to our ping request
    if (icmp_header->icmp_type == ICMP_ECHOREPLY && icmp_header->icmp_id == getpid() & 0xFFFF) {
        printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.2f ms\n",
               bytes_received - sizeof(struct iphdr) - sizeof(struct icmp),
               inet_ntoa(from.sin_addr),
               icmp_header->icmp_seq,
               ip_header->ttl,
               (double) (tv.tv_sec * 1000 + tv.tv_usec / 1000) - (double) icmp_header->icmp_data);
        return 1;
    }

    return 0;
}

int main(int argc, char **argv)
