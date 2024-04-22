// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "xdp-pktgen.skel.h"
#include "test_udp_pkt.h"
#include <thread>
#include <vector>

struct config {
	int ifindex = 6;
	int xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
	int repeat = 1024;
	int batch_size = 16;
};
struct config cfg;

struct stats {
	uint64_t error_count = 0;
	uint64_t processed_count = 0;
};
struct stats global_stats;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

void print_stats() {
    while (!exiting) {
        sleep(1);
		static uint64_t last_error_count = 0;
		static uint64_t last_processed_count = 0;

		uint64_t processed_count = global_stats.processed_count;
		uint64_t error_count = global_stats.error_count;
		uint64_t avg_errors = error_count - last_error_count;
		uint64_t avg_processed = processed_count - last_processed_count;
		printf("Avg Tx Errors: %lld Pkt/s, Avg Tx: %lld\n Pkt/s", avg_errors, avg_processed);
		last_error_count = error_count;
		last_processed_count = processed_count;
    }
}

int test_run_xdp_programs(int fd, int thread_id)
{
	int err;
	struct udp_packet pkt_udp = create_test_udp_packet();
	char data[sizeof(pkt_udp) + sizeof(__u64)];
	struct xdp_md ctx_in = { .data = sizeof(__u64),
				 .data_end = sizeof(data) };
	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
			    .data_in = &data,
			    .data_size_in = sizeof(data),
			    // .ctx_in = &ctx_in,
			    // .ctx_size_in = sizeof(ctx_in),
			    .repeat = cfg.repeat,
			    .flags = BPF_F_TEST_XDP_LIVE_FRAMES,
				.cpu = thread_id,
			    .batch_size = cfg.batch_size
		);
	memcpy(&data[sizeof(__u64)], &pkt_udp, sizeof(pkt_udp));
	// start the test
    int result = bpf_prog_test_run_opts(fd, &opts);
	if (result) {
		static int once = 1;
		if (once) {
			once = 0;
			printf("Error running program: %d\n", result);
		}
		global_stats.error_count++;
		return 1;
	} else {
		global_stats.processed_count++;
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct xdp_pktgen_bpf *skel;
	int err;
	int redirect_fd, pass_fd;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = xdp_pktgen_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = xdp_pktgen_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		return 1;
	}
	redirect_fd = bpf_program__fd(skel->progs.xdp_redirect_notouch);
	pass_fd = bpf_program__fd(skel->progs.xdp_pass_notouch);
	skel->bss->ifindex = cfg.ifindex;

	// err = bpf_xdp_attach(cfg.ifindex, redirect_fd,
	// 						 cfg.xdp_flags,
	// 						 nullptr);
	// if (err) {
	// 	printf("attach xdp programs error\n");
	// }

	std::thread monitor_thread(print_stats);
	/* Process events */
	while (!exiting) {
		test_run_xdp_programs(redirect_fd, 0);
	}

	monitor_thread.join();
	/* Clean up */
	xdp_pktgen_bpf__destroy(skel);
	bpf_xdp_detach(cfg.ifindex, cfg.xdp_flags, NULL);
	return err < 0 ? -err : 0;
}
