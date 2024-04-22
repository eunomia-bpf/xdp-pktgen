#ifndef TEST_UDP_PKT_H
#define TEST_UDP_PKT_H

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_link.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/in6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <linux/netdev.h>

struct udp_packet
{
    struct ethhdr eth;
    struct ipv6hdr iph;
    struct udphdr udp;
    __u8 payload[64 - sizeof(struct udphdr) - sizeof(struct ethhdr) - sizeof(struct ipv6hdr)];
} __packed;

inline struct udp_packet create_test_udp_packet(void)
{
    struct udp_packet pkt = {0};

    // Ethernet header
    pkt.eth.h_proto = __bpf_constant_htons(ETH_P_IPV6);
    // b8:3f:d2:2a:e5:11
    memcpy(pkt.eth.h_dest, (const unsigned char[]){0xb8, 0x3f, 0xd2, 0x2a, 0xe5, 0x11}, sizeof(pkt.eth.h_dest));
    // b8:3f:d2:2a:e7:69
    memcpy(pkt.eth.h_source, (const unsigned char[]){0xb8, 0x3f, 0xd2, 0x2a, 0xe7, 0x69}, sizeof(pkt.eth.h_source));
    
    // IPv6 header
    pkt.iph.version = 6;
    pkt.iph.nexthdr = IPPROTO_UDP;
    pkt.iph.payload_len = bpf_htons(sizeof(struct udp_packet) - offsetof(struct udp_packet, udp));
    pkt.iph.hop_limit = 2;
    // Manually initializing the IPv6 address
    __u16 saddr_init[8] = {bpf_htons(0xfc00), 1, 0, 0, 0, 0, 0, bpf_htons(1)};
    __u16 daddr_init[8] = {bpf_htons(0xfc00), 2, 0, 0, 0, 0, 0, bpf_htons(2)};
    memcpy(&pkt.iph.addrs.saddr, saddr_init, sizeof(pkt.iph.addrs.saddr));
    memcpy(&pkt.iph.addrs.daddr, daddr_init, sizeof(pkt.iph.addrs.daddr));
    static_assert(sizeof(pkt.iph.addrs.saddr) == sizeof(saddr_init), "IPv6 address size mismatch");

    // UDP header
    pkt.udp.source = bpf_htons(1);
    pkt.udp.dest = bpf_htons(1);
    pkt.udp.len = bpf_htons(sizeof(struct udp_packet) - offsetof(struct udp_packet, udp));

    // Payload
    memset(pkt.payload, 0x42, sizeof(pkt.payload)); // Assuming you want the payload initialized to 0x42.
    return pkt;
}

#endif // TEST_UDP_PKT_H
