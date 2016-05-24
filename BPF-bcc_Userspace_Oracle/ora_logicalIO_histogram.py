#!/usr/bin/python
#
# ora_logicalIO_histogram.py - Oracle logical IO latency histogram using BPF/bcc and uprobes
#
# USAGE: ora_logicalIO_histogram.py [-h] [-p PID]
#
# Note: this probe measures the latency between call and return for the Oracle function kcbgtcr,
#       which is an important part of the logical IO processing for consistent reads
#
# Author: Luca.Canali@cern.ch - April 2016
# Licensed under the Apache License, Version 2.0 (the "License")
#
# Credits: 
#  example scripts in bcc repository, in particular by @BrendanGregg
#  @FritsHoogland for collaboration on investigations of Oracle internals 
#  and userspace tracing
#

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import ctypes as ct
import argparse
import os

examples = """examples:
    ./ora_logicalIO_histogram.py 1 10         # Oracle kcbgtcr latency histograms, 1-second summary, repeat 10 times
    ./ora_logicalIO_histogram.py -p 123  1 10 # trace PID 123 only
"""

parser = argparse.ArgumentParser(
    description="Oracle logical IO latency histogram for consistent reads\nrequires the environment variable ORACLE_HOME\nrun as root",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid",
    help="trace PID only")
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("interval", nargs="?", default=99999999,
    help="measurement interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")	
args = parser.parse_args()
countdown = int(args.count)

# full path of the oracle executable
oracle_executable = os.path.expandvars("$ORACLE_HOME/bin/oracle")
if not os.path.isfile(oracle_executable):
    exit("Oracle executable not found.\nPlease set the environment variable ORACLE_HOME.")

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>

BPF_HASH(hasht_duration, u32);
BPF_HISTOGRAM(hist_logicalio);

int in_kcbgtcr(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    if (FILTER)
        return 0;
    u64 ts = bpf_ktime_get_ns();
    hasht_duration.update(&pid, &ts);
	return 0;
};

int out_kcbgtcr(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    if (FILTER)
        return 0;
    u64 t1 = bpf_ktime_get_ns();
    u64 *t0 = hasht_duration.lookup(&pid);
	if (t0) {
       u64 delta_time = t1 - *t0;
       hist_logicalio.increment(bpf_log2l(delta_time));
	}
	return 0;
};
"""

# code substitutions
if args.pid:
    bpf_text = bpf_text.replace('FILTER', 'pid != %s' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER', '0')

b = BPF(text=bpf_text)
b.attach_uprobe(name=oracle_executable, sym="kcbgtcr", fn_name="in_kcbgtcr")
b.attach_uretprobe(name=oracle_executable, sym="kcbgtcr", fn_name="out_kcbgtcr")

# output

exiting = 0 if args.interval else 1
hist_logicalio = b.get_table("hist_logicalio")

# Start tracing
print("Latency histograms for kcbgtcr, Oracle logical IO for consistent read... Hit Ctrl-C to end.")

while (1):
    try:
        sleep(int(args.interval))
    except KeyboardInterrupt:
        exiting = 1

    print()
    if args.timestamp:
        print("%-8s\n" % strftime("%H:%M:%S"), end="")

    hist_logicalio.print_log2_hist("kcbgtcr latency, ns", "", section_print_fn=int)
    hist_logicalio.clear()

    countdown -= 1
    if exiting or countdown == 0:
        exit()

