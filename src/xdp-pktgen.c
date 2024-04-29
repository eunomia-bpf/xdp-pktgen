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


static bool status_exited = false;
static bool runners_exited = false;

int run_prog_fd = 0;

static int run_prog()
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
			    .repeat = 1 << 20,
			    .flags = BPF_F_TEST_XDP_LIVE_FRAMES,
			    .batch_size = 0,
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
	} while (1);
	return 0;
}


// static int probe_kernel_support(void)
// {
// 	DECLARE_LIBXDP_OPTS(xdp_program_opts, opts);
// 	struct xdp_trafficgen *skel;
// 	struct xdp_program *prog;
// 	int data = 0, err;
// 	bool status = 0;

// 	skel = xdp_trafficgen__open();
// 	if (!skel) {
// 		err = -errno;
// 		pr_warn("Couldn't open XDP program: %s\n", strerror(-err));
// 		return err;
// 	}

// 	err = sample_init_pre_load(skel, "lo");
// 	if (err < 0) {
// 		pr_warn("Failed to sample_init_pre_load: %s\n", strerror(-err));
// 		goto out;
// 	}

// 	opts.obj = skel->obj;
// 	opts.prog_name = "xdp_drop";

// 	prog = xdp_program__create(&opts);
// 	if (!prog) {
// 		err = -errno;
// 		pr_warn("Couldn't load XDP program: %s\n", strerror(-err));
// 		goto out;
// 	}

// 	const struct thread_config cfg = {
// 		.pkt = &data,
// 		.pkt_size = sizeof(data),
// 		.num_pkts = 1,
// 		.batch_size = 1,
// 		.prog = prog
// 	};
// 	err = run_prog(&cfg, &status);
// 	if (err == -EOPNOTSUPP) {
// 		pr_warn("BPF_PROG_RUN with batch size support is missing from libbpf.\n");
// 	}  else if (err == -EINVAL) {
// 		err = -EOPNOTSUPP;
// 		pr_warn("Kernel doesn't support live packet mode for XDP BPF_PROG_RUN.\n");
// 	} else if (err) {
// 		pr_warn("Error probing kernel support: %s\n", strerror(-err));
// 	}

// 	xdp_program__close(prog);
// out:
// 	xdp_trafficgen__destroy(skel);
// 	return err;
// }

int main()
{
	struct xdp_pktgen_bpf *skel = NULL;
	pthread_t *runner_threads = NULL;
	int err = 0, i;
	char buf[100];
	__u32 key = 0;

	// err = probe_kernel_support();
	// if (err)
	// 	return err;

	skel = xdp_pktgen_bpf__open();
	if (!skel) {
		err = -errno;
		printf("Couldn't open XDP program: %s\n", strerror(-err));
		goto out;
	}

	err = xdp_pktgen_bpf__load(skel);
	if (err)
		goto out;
	run_prog_fd = bpf_program__fd(skel->progs.xdp_redirect_notouch);

	status_exited = true;
	run_prog();

out:
	xdp_pktgen_bpf__destroy(skel);
    return err;
}
