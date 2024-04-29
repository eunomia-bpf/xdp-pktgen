/* SPDX-License-Identifier: MIT */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <bpf/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include "xdp-pktgen.skel.h"
#include "test_udp_pkt.h"

#ifndef BPF_F_TEST_XDP_LIVE_FRAMES
#define BPF_F_TEST_XDP_LIVE_FRAMES	(1U << 1)
#endif

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}


struct config {
	int ifindex;
	int xdp_flags;
	int repeat;
	int batch_size;
};

struct config cfg = {
	.ifindex = 6,
	.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST,
	.repeat = 1 << 20,
	.batch_size = 0,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int run_prog(int run_prog_fd, int count)
{
	struct test_udp_packet pkt_udp = create_test_udp_packet();
	struct xdp_md ctx_in = {
		.data_end = sizeof(pkt_udp),
	};

	printf("pkt size: %ld\n", sizeof(pkt_udp));
	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
			    .data_in = &pkt_udp,
			    .data_size_in = sizeof(pkt_udp),
			    .ctx_in = &ctx_in,
			    .ctx_size_in = sizeof(ctx_in),
			    .repeat = cfg.repeat,
			    .flags = BPF_F_TEST_XDP_LIVE_FRAMES,
			    .batch_size = cfg.batch_size,
				.cpu = 0,
		);
	__u64 iterations = 0;
	cpu_set_t cpu_cores;
	int err;

	CPU_ZERO(&cpu_cores);
	CPU_SET(0, &cpu_cores);
	pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu_cores);
	do {
		err = bpf_prog_test_run_opts(run_prog_fd, &opts);
		if (err)
			return -errno;
		iterations += opts.repeat;
	} while ((count == 0 || iterations < count) && !exiting);
	return 0;
}

static int probe_kernel_support(int run_prog_fd)
{
	int err = run_prog(run_prog_fd, 1);
	if (err == -EOPNOTSUPP) {
		printf("BPF_PROG_RUN with batch size support is missing from libbpf.\n");
	}  else if (err == -EINVAL) {
		err = -EOPNOTSUPP;
		printf("Kernel doesn't support live packet mode for XDP BPF_PROG_RUN.\n");
	} else if (err) {
		printf("Error probing kernel support: %s\n", strerror(-err));
	} else {
		printf("Kernel supports live packet mode for XDP BPF_PROG_RUN.\n");
	}
	return err;
}

int main()
{
	struct xdp_pktgen_bpf *skel = NULL;
	int err = 0, i;
	__u32 key = 0;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);
	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = xdp_pktgen_bpf__open();
	if (!skel) {
		err = -errno;
		printf("Couldn't open XDP program: %s\n", strerror(-err));
		goto out;
	}
	skel->bss->target_ifindex = cfg.ifindex;

	err = xdp_pktgen_bpf__load(skel);
	if (err)
		goto out;

	int run_prog_fd = bpf_program__fd(skel->progs.xdp_redirect_notouch);
	// probe kernel support for BPF_PROG_RUN
	err = probe_kernel_support(run_prog_fd);
	if (err)
		return err;
	
	// err = bpf_xdp_attach(cfg.ifindex, run_prog_fd,
	// 						 cfg.xdp_flags,
	// 						 NULL);
	// if (err) {
	// 	printf("attach xdp programs error\n");
	// }
	// printf("xdp program attached to %d\n", cfg.ifindex);
	run_prog(run_prog_fd, 0);

out:
	xdp_pktgen_bpf__destroy(skel);
	// bpf_xdp_detach(cfg.ifindex, cfg.xdp_flags, NULL);
    return err;
}
