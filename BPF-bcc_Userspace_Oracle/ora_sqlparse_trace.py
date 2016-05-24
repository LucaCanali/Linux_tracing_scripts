#!/usr/bin/python
#
# ora_sqlparse_trace.py   Basic tracing of Oracle hard parsing using BPF/bcc and uprobes
#
# USAGE: ora_sqlparse_trace.py [-h] [-p PID]
#
# This traces the sql hard parsing on Oracle binaries hooking on opiprs
# It is a port of previous work with SystemTap and perf probes.
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
    ./ora_sqlparse_trace.py         # trace Oracle sql hard parsing 
    ./ora_sqlparse_trace.py -p 123  # trace PID 123 only
"""

parser = argparse.ArgumentParser(
    description="Oracle sql hard parse tracing\nrequires the environment variable ORACLE_HOME\nrun as root",
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
    u64 len;
    char sql[400];
};

BPF_PERF_OUTPUT(events);

int trace_opiprs(struct pt_regs *ctx) {
    struct str_t data  = {};
    u32 pid;
    pid = bpf_get_current_pid_tgid();
    if (FILTER)
        return 0;
    data.pid = pid;
    data.len = ctx->dx;
    bpf_probe_read(&data.sql, sizeof(data.sql), (void *)ctx->si);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
};
"""
STR_DATA = 400   # match definition of str_t.sql, SQL text display will be trunctaced at this length

# code substitutions
if args.pid:
    bpf_text = bpf_text.replace('FILTER', 'pid != %s' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER', '0')

class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_ulong),
        ("len", ct.c_ulonglong),
        ("sql", ct.c_char * STR_DATA)
    ]

b = BPF(text=bpf_text)
b.attach_uprobe(name=oracle_executable, sym="opiprs", fn_name="trace_opiprs")

# Start tracing
print("Start tracing Oracle hard parsing... Hit Ctrl-C to end.")

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    print("%-9s pid=%d len=%d sql=%s" % (strftime("%H:%M:%S"), event.pid, event.len, event.sql))

b["events"].open_perf_buffer(print_event)
while 1:
    b.kprobe_poll()

