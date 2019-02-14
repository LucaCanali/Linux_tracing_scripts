head	1.1;
access;
symbols;
locks; strict;
comment	@# @;


1.1
date	2019.02.14.15.03.33;	author root;	state Exp;
branches;
next	;


desc
@@


1.1
log
@Initial revision
@
text
@#!/usr/bin/python
#
# ora_wait_trace.py - Basic oracle wait event tracing using BPF/bcc and uprobes
#
# This script traces Oracle sessions by hooking on the functions "kskthewt" and 
# "kews_update_wait_time" and reads from function arguments (CPU registers).
# This code is experimental and a proof of concept. Use at your own risk.
#
# Usage: ora_wait_trace.py [-h] [-p PID]
#
# Use together with eventsname.sql and eventsname.sed for resolving event# into event name
# generate eventsname.sed from sqlplus using the scrip eventsname.sql
# Example:
# ./ora_waittrace.py -p 123| sed -f eventsname.sed
#
# Example for the streaming mode using stdbuf to avois buffering effects:
# stdbuf -oL ./ora_wait_trace.py -p 123| sed -f ~oracle/luca/eventsname.sed
#
# Author: Luca.Canali@@cern.ch - April 2016
# Licensed under the Apache License, Version 2.0 (the "License")
#
# Credits: 
#  example scripts in bcc repository, in particular by @@BrendanGregg
#  @@FritsHoogland for collaboration on investigations of Oracle internals 
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

# workaround for Oracle 12c and higher
# need to attach the address of the probe + 2
address_list = BPF.get_user_functions_and_addresses(oracle_executable, "kskthewt")
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

# Start tracing
print("Start tracing oracle wait events... Hit Ctrl-C to end.")

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    print("%-9s pid=%d event#=%d wait_time=%d" % (strftime("%H:%M:%S"), event.pid, event.event, event.wait_time))

b["events"].open_perf_buffer(print_event)
while 1:
    b.kprobe_poll()

@
