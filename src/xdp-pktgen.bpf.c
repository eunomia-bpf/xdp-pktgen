/* SPDX-License-Identifier: MIT */
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char _license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_redirect_notouch(struct xdp_md *ctx)
{
	return bpf_redirect(6, 0);
}
