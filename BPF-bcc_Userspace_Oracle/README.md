# BPF/bcc scripts for Oracle tracing

Author: Luca.Canali@cern.ch
First release: April 2016

This folder contains example scripts for tracing Oracle database processes, hooking probes on at the userspace. The scripts use Linux eBPF with bcc and uprobes.
The provided scripts are ports of previous work done with SystemTap and/or Perf and are intended as learning material not for production usage, originally developed for Oracle troubleshooting and investigations of Oracle internals.

| Script                     | Short description
| -------------------------- | -------------------------------------------------------------------------------------
| [ora_sqlparse_trace.py](ora_sqlparse_trace.py) | Tracing of Oracle SQL parsing. This script traces the SQL hard parsing on Oracle binaries hooking on opiprs and reads from function arguments (CPU registers) and from process memory.
| [ora_wait_trace.py](ora_wait_trace.py)         |  Tracing of Oracle wait events. This probe traces Oracle sessions by hooking on the functions kskthewt and kews_update_wait_time and reads from function aguments (CPU registers).
| [ora_logicalIO_histogram.py](ora_logicalIO_histogram.py) | Logical IO latency histograms. This probe measures the latency between call and return for the Oracle function kcbgtcr, which is an important part of the logical IO processing for consistent reads
| [ora_wait_histogram.py](ora_wait_histogram.py) | Wait event latency histograms. This probe traces Oracle sessions by hooking on the functions kskthewt and kews_update_wait_time and reads from function arguments (CPU registers)

Compatibility and issues:

- Use kernel version 4.5 or higher (tested on Fedora 24 beta)
- Oracle version: developed and tested for Oracle 11.2.0.4
- Oracle 12c currently not supported due to an issue that originates with uprobes (also affecting similar scripts using Perf and SystemTap)
- The scripts provided here are experimental and may cause unwanted effects especially on busy systems, and overall may be incompatible with your current set-up and/or need some tweaking before running

Credits and acknowledgements:

- [Brendan Gregg](https://twitter.com/brendangregg) for writing many of the example tools/scripts for bcc which have been used as guide for writing the scripts in this folder
- BPF and [bcc](https://github.com/iovisor/bcc) development teams
- [Frits Hoogland](https://twitter.com/fritshoogland) for collaboration on investigating Oracle internals and userspace tracing.


