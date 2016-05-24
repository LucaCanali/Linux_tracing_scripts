#!/usr/bin/python
#
# ora_wait_trace.py - Basic oracle wait event tracing using BPF/bcc and uprobes
#
# USAGE: ora_wait_trace.py [-h] [-p PID]
#
# use together with eventsname.sql and eventsname.sed for resolving event# into event name
# generate eventsname.sed from sqlplus using the scrip eventsname.sql
# Example:
# ./ora_waittrace.py -p 123| sed -f eventsname.sed
#
# Example for the streaming mode using stdbuf to avois buffering effects:
# stdbuf -oL ./ora_wait_trace.py -p 123| sed -f ~oracle/luca/eventsname.sed
#
# This traces the wait events on Oracle binaries hooking on functions kskthewt and 
# kews_update_wait_time. It is a port of previous work with SystemTap and perf probes.
# This code is experimental and a proof of concept. Use at your own risk.
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
from time import strftime
import ctypes as ct
import argparse
import os

examples = """examples:
    export ORACLE_HOME=/u01/app/oracle/product/11.2.0.4/rdbms
    ./ora_wait_trace.py         # trace Oracle wait events
    ./ora_wait_trace.py -p 123  # trace PID 123 only
"""

parser = argparse.ArgumentParser(
    description="Trace Oracle wait events with BPF/bcc\nrequires the environment variable ORACLE_HOME\nrun as root",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid",
    help="trace PID only")
args = parser.parse_args()

# full path of the oracle executable
oracle_executable = os.path.expandvars("$ORACLE_HOME/bin/oracle")
if not os.path.isfile(oracle_executable):
    exit("Oracle executable not found.\nPlease set the environment variable ORACLE_HOME.")

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>

struct str_t {
    u32 pid;
    u64 event;
    u64 wait_time;
};

BPF_HASH(wait_time, u32);
BPF_PERF_OUTPUT(events);

int trace_kskthewt(struct pt_regs *ctx) {
    struct str_t data  = {};
    u32 pid;
    u64 *wt;
    pid = bpf_get_current_pid_tgid();
    if (FILTER)
        return 0;
    data.pid = pid;
    data.event = ctx->si;
    wt = wait_time.lookup(&pid);
    if (wt)
      data.wait_time = *wt;
    else
      data.wait_time = 0;
    events.perf_submit(ctx, &data, sizeof(data));
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

class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_ulong),
        ("event", ct.c_ulonglong),
        ("wait_time", ct.c_ulonglong)
    ]

b = BPF(text=bpf_text)
b.attach_uprobe(name=oracle_executable, sym="kskthewt", fn_name="trace_kskthewt")
b.attach_uprobe(name=oracle_executable, sym="kews_update_wait_time", fn_name="trace_kews_update_wait_time")

# Start tracing
print("Start tracing oracle wait events... Hit Ctrl-C to end.")

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    print("%-9s pid=%d event#=%d wait_time=%d" % (strftime("%H:%M:%S"), event.pid, event.event, event.wait_time))

b["events"].open_perf_buffer(print_event)
while 1:
    b.kprobe_poll()

