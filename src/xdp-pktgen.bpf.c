// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int ifindex = 0;

SEC("xdp")
int xdp_redirect_notouch(struct xdp_md *ctx)
{
	return bpf_redirect(ifindex, 0);
}

SEC("xdp")
int xdp_pass_notouch(struct xdp_md *ctx)
{
	return XDP_PASS;
}