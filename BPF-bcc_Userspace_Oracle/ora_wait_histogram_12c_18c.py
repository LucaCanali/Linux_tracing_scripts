#!/usr/bin/python
#
# ora_wait_histogram.py - Oracle wait event latency histograms using BPF/bcc and uprobes
#
# This script traces Oracle sessions by hooking on the functions "kskthewt" and 
# "kews_update_wait_time" and reads from function arguments (CPU registers). BPF computes 
# the latency histogram for the wait events and the script prints the values on stdout.
# This code is experimental and a proof of concept. Use at your own risk.
#
# Usage: ora_wait_histogram.py [-h] [-p PID]
#
# use together with eventsname.sql and eventsname.sed for resolving event# into event name
# generate eventsname.sed from sqlplus using the scrip eventsname.sql
# Example:
# ./ora_wait_histogram -p 123| sed -e 's/event# = /event#=/g' -f eventsname.sed
#
# Example for streaming mode:
# stdbuf -oL ./ora_wait_histogram -p 123| sed -e 's/event# = /event#=/g' -f eventsname.sed
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
    ./ora_wait_histogram.py 1 10        # Oracle event histograms, 1-second summary every 10 seconds
    ./ora_wait_histogram.py -p 123 1 10 # trace PID 123 only
"""

parser = argparse.ArgumentParser(
    description="Oracle wait event histograms\nrequires the environment variable ORACLE_HOME\nrun as root",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid",
    help="trace PID only")
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("interval", nargs="?", default=99999999,
    help="output interval, in seconds")
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

typedef struct str_event {
    u64 event;
    u64 wait_time;
} str_event_t;

BPF_HASH(wait_time, u32);
BPF_HISTOGRAM(eventhist, str_event_t);
	
int trace_kskthewt(struct pt_regs *ctx) {
    str_event_t data  = {};
    u32 pid;
    u64 *wt;
    pid = bpf_get_current_pid_tgid();
    if (FILTER)
        return 0;
    data.event = ctx->si;
    wt = wait_time.lookup(&pid);
    if (wt)
      data.wait_time = bpf_log2l(*wt);
    else
      data.wait_time = 0;

	eventhist.increment(data);
    return 0;
};

int trace_kews_update_wait_time(struct pt_regs *ctx) {
    u32 pid;
    u64 rsi;
    pid = bpf_get_current_pid_tgid();
    if (FILTER)
        return 0;
    rsi = ctx->si;
    if (rsi > 0)
        wait_time.update(&pid, &rsi);
    return 0;
};

"""

# code substitutions
if args.pid:
    bpf_text = bpf_text.replace('FILTER', 'pid != %s' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER', '0')

b = BPF(text=bpf_text)

# workaround for Oracle 12c and higher
# need to attach the address of the probe + 2
address_list = BPF.get_user_functions_and_addresses(oracle_executable, "^kskthewt$")
paddr = address_list[0][1] + 2
b.attach_uprobe(name=oracle_executable, addr=paddr, fn_name="trace_kskthewt")


# This is the original code, works on Oracle 11c then breaks for higher versions
# b.attach_uprobe(name=oracle_executable, sym="kskthewt", fn_name="trace_kskthewt")

# workaround for Oracle 12c and higher
# need to attach the address of the probe + 2
address_list = BPF.get_user_functions_and_addresses(oracle_executable, "^kews_update_wait_time$")
paddr = address_list[0][1] + 2
b.attach_uprobe(name=oracle_executable, addr=paddr, fn_name="trace_kews_update_wait_time")

# This is the original code, works on Oracle 11c then breaks for higher versions
# b.attach_uprobe(name=oracle_executable, sym="kews_update_wait_time", fn_name="trace_kews_update_wait_time")

# output

exiting = 0 if args.interval else 1
eventhist = b.get_table("eventhist")

# Start tracing
print("Start tracing oracle wait events... Hit Ctrl-C to end.")

while (1):
    try:
        sleep(int(args.interval))
    except KeyboardInterrupt:
        exiting = 1

    print()
    if args.timestamp:
        print("Time = %-8s\n" % strftime("%H:%M:%S"), end="")

    eventhist.print_log2_hist("wait time, microsec", "event#", section_print_fn=int)
    eventhist.clear()

    countdown -= 1
    if exiting or countdown == 0:
        exit()
		

