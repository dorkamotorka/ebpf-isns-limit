//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define NUM_LOOPS 100000000

/* for loop with unroll directive*/

SEC("xdp")
int xdp_prog_for_loop_unroll(struct xdp_md *ctx) {
  int counter = 0;

// Standard for loop with unroll directive
#pragma clang loop unroll(full)
  for (int i = 0; i < NUM_LOOPS; i++) {
    counter++;
    bpf_printk("Counting...");
  }

  bpf_printk("Counted %dx times", counter);

  return XDP_PASS;
}
