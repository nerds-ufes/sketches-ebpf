# ebpf-cms-toy

![License](https://img.shields.io/badge/license-GPL--2.0-blue)
![Language](https://img.shields.io/badge/language-C-blue)
![eBPF](https://img.shields.io/badge/eBPF-TC%20egress-orange)
![Kernel](https://img.shields.io/badge/kernel-%E2%89%A55.8-green)
![Arch](https://img.shields.io/badge/arch-x86__64-lightgrey)
![Topic](https://img.shields.io/badge/topic-Count--Min%20Sketch-purple)
![GitHub last commit](https://img.shields.io/github/last-commit/nerds-ufes/sketches-ebpf)
![GitHub repo size](https://img.shields.io/github/repo-size/nerds-ufes/sketches-ebpf)

A didactic implementation of a **Count-Min Sketch (CMS)** in eBPF/TC egress to collect per-flow packet statistics without storing exact flow state. Designed as a toy example for teaching probabilistic data structures applied to network monitoring.

## Overview

Instead of maintaining an exact counter per flow — which requires unbounded memory — this project uses a Count-Min Sketch attached to the TC egress hook of a Linux network interface. The sketch estimates the packet count for any 5-tuple flow using a fixed-size matrix of counters, trading a small, bounded error for significant memory savings.

The pipeline is:

```
Outgoing packets
      │
      ▼
┌─────────────────────────┐
│  TC egress hook (eBPF)  │  ← cms_kern.c
│  • parse 5-tuple        │
│  • update CMS matrix    │
│  • update exact map     │
└─────────────────────────┘
      │
      ▼
  BPF maps (kernel)
      │
      ▼
┌─────────────────────────┐
│  Userspace report       │  ← cms_user.c
│  • query CMS            │
│  • compare with exact   │
│  • show error %         │
└─────────────────────────┘
```

## What is a Count-Min Sketch?

A Count-Min Sketch is a probabilistic data structure that estimates the frequency of elements in a data stream using a matrix of `d × w` counters, where:

- `d` (rows) — number of independent hash functions
- `w` (cols) — number of buckets per row

Each incoming element is hashed `d` times, incrementing one counter per row. The estimated count is the **minimum** across all rows, which gives the CMS its name and its key property: it **never underestimates**, only overestimates.

The theoretical guarantees are:

```
P[ sketch(f) > exact(f) + ε × N ] ≤ δ

ε = e / w    (maximum absolute error fraction)
δ = e^(-d)   (probability of exceeding ε)
N            (total number of elements inserted)
```

## Flow Key (5-tuple)

Each packet is identified by:

| Field | Type | Description |
|---|---|---|
| `src_ip` | `__u32` | Source IPv4 address |
| `dst_ip` | `__u32` | Destination IPv4 address |
| `src_port` | `__u16` | Source port (TCP/UDP) |
| `dst_port` | `__u16` | Destination port (TCP/UDP) |
| `protocol` | `__u8` | IP protocol (1=ICMP, 6=TCP, 17=UDP) |

## Project Structure

```
ebpf-cms-toy/
├── cms.h          # Shared parameters (CMS_ROWS, CMS_COLS, seeds)
├── cms_kern.c     # eBPF program — TC egress hook
├── cms_user.c     # Userspace loader, reporter, and cleaner
├── Makefile
├── init.sh        # Load CMS onto interface
├── test.sh        # Generate demo traffic (ping, HTTP, download)
└── stop.sh        # Send SIGINT, print report, clean up
```

## Requirements

- Ubuntu Server 24.04 VM (Virtualbox)
-- user: ebpf-admin
-- passwd: ebpf
- clang ≥ 10
- libbpf-dev
- iproute2 ≥ 5.x (`tc` with eBPF support)
- bpftool

Install on Ubuntu/Debian:

```bash
sudo apt install clang llvm libbpf-dev linux-headers-$(uname -r) iproute2 bpftool
```

## Building

```bash
# Generate vmlinux.h from the running kernel (required)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Compile
make
```

## Running the Demo

The demo is split into three scripts for clarity:

```bash
# Terminal 1 — load the eBPF program onto the interface
./init.sh <interface>

# Terminal 2 — generate traffic (ping + HTTP GETs + large download)
./test.sh

# Either terminal — stop, print report, clean up
./stop.sh
```

Example output with a small sketch (`CMS_ROWS=4, CMS_COLS=1024`):

```
SRC_IP               DST_IP               SPORT    DPORT    PROTO  |      EXACT     SKETCH  ABS_ERR   ERR%
10.9.1.85            8.8.8.8              0        0        1      |         20         20        0   0.00%
10.9.1.85            44.216.249.42        38950    80       6      |          7          7        0   0.00%
10.9.1.85            200.137.66.240       41121    53       17     |          1          1        0   0.00%
10.9.1.85            10.9.1.225           22       47832    6      |        340        340        0   0.00%
```

## Observing Collisions

To observe the CMS error empirically, reduce the sketch size in `cms.h`:

```c
// Tiny sketch — frequent collisions
#define CMS_ROWS  2
#define CMS_COLS  32
```

```bash
make && ./init.sh <interface> && ./test.sh && ./stop.sh
```

Expected output with collisions:

```
SRC_IP               DST_IP               SPORT    DPORT    PROTO  |      EXACT     SKETCH  ABS_ERR    ERR%
10.9.1.85            8.8.8.8              0        0        1      |         20         20        0    0.00%
10.9.1.85            200.137.66.240       50396    53       17     |          1          8        7  700.00%
10.9.1.85            34.234.10.121        53068    80       6      |          6         13        7  116.67%
10.9.1.85            10.9.1.225           22       47832    6      |         91         91        0    0.00%
```

Key observations:

- The sketch **never underestimates** — all `SKETCH ≥ EXACT`
- **Heavy hitters** (high-volume flows like SSH) remain accurate even with collisions
- **Small flows** (DNS, single requests) are most affected by overestimation
- The absolute error stays bounded by `ε × N`, consistent with the theoretical guarantee

## Sketch Size Trade-off

| Configuration | CMS_ROWS | CMS_COLS | Memory | Expected error |
|---|---|---|---|---|
| Tiny | 2 | 32 | 512 B | high |
| Default | 4 | 1024 | 32 KB | ~0% for light traffic |
| Conservative | 6 | 4096 | 192 KB | negligible |

## Implementation Notes

- The eBPF program uses `BPF_MAP_TYPE_PERCPU_ARRAY` for the CMS matrix to avoid atomic contention across CPU cores. Userspace sums all per-CPU values before computing the minimum.
- An auxiliary `BPF_MAP_TYPE_HASH` stores exact counts per flow for comparison — this is only for didactic purposes and would not exist in a real deployment.
- The TC egress hook (`BPF_PROG_TYPE_SCHED_CLS`) was chosen over XDP because outgoing traffic is not available at the XDP hook.
- Hash functions use a Murmur-inspired mixing with distinct seeds per row to minimize correlation between rows.

## License

GPL-2.0
