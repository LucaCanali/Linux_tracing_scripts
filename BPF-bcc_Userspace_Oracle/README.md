# BPF/bcc scripts for Oracle tracing

Author: Luca.Canali@cern.ch  
First release: April 2016  
Update February 2019

See also: http://externaltable.blogspot.com/2016/05/linux-bpfbcc-for-oracle-tracing.html

This folder contains example scripts for tracing Oracle database processes with bcc/BPF.
It works by hooking probes on the userspace. The scripts use Linux eBPF with bcc and uprobes.  
The interest to do this is to provide tools and methods to combine userspace tracing of Oracle
with the great instrumentation power of dynamic instrumentation probes on the OS with bcc/BPF.
The scripts are ports of previous work done with SystemTap and/or Perf and are intended as learning
 material not for production usage.
 

| Script                     | Short description
| -------------------------- | -------------------------------------------------------------------------------------
| [ora_sqlparse_trace.py](ora_sqlparse_trace.py) | Tracing of Oracle SQL parsing. This script traces the SQL hard parsing on Oracle binaries hooking on opiprs and reads from function arguments (CPU registers) and from process memory.
| [ora_sqlparse_trace_12c_18c.py](ora_sqlparse_trace_12c_18c.py) | For 12c and higher. Tracing of Oracle SQL parsing. This script traces the SQL hard parsing on Oracle binaries hooking on opiprs and reads from function arguments (CPU registers) and from process memory.
| [ora_wait_trace.py](ora_wait_trace.py)         |  Tracing of Oracle wait events. This probe traces Oracle sessions by hooking on the functions kskthewt and kews_update_wait_time and reads from function aguments (CPU registers).
| [ora_wait_trace_12c_18c.py](ora_wait_trace_12c_18c.py)         |  For 12c and higher. Tracing of Oracle wait events. This probe traces Oracle sessions by hooking on the functions kskthewt and kews_update_wait_time and reads from function aguments (CPU registers).
| [ora_wait_histogram_12c_18c.py](ora_wait_histogram_12c_18c.py) | For 12c and higher. Wait event latency histograms. This probe traces Oracle sessions by hooking on the functions kskthewt and kews_update_wait_time and reads from function arguments (CPU registers)
| [ora_wait_histogram.py](ora_wait_histogram.py) | Wait event latency histograms. This probe traces Oracle sessions by hooking on the functions kskthewt and kews_update_wait_time and reads from function arguments (CPU registers)
| [ora_logicalIO_histogram.py](ora_logicalIO_histogram.py) | Logical IO latency histograms. This probe measures the latency between call and return for the Oracle function kcbgtcr, which is an important part of the logical IO processing for consistent reads

Compatibility and issues:

- Must have a kernel with BPF enabled. You can use Red Hat/ Oracle Linux 7.6 or higher (`yum install bcc*`)
  or use a system with Linux kernel version 4.5 or higher. 
- Oracle version: these scripts have been developed and tested for Oracle 11.2.0.4
- New in February 2019, a version for 12c and higher of 3 scripts implement a workaround for the issues with Oracle
 and uprobes in those versions. Tested with Oracle 18c.
  - The workaround is simple and consists in tracing the next instruction (for example kskthewt+2 instead of kskthewt), 
  see [Oracle12_and_Perf](https://mahmoudhatem.wordpress.com/2017/03/22/workaround-for-linux-perf-probes-issue-for-oracle-tracing/)
- The scripts provided here are experimental and may cause unwanted effects especially on busy systems, and overall may be incompatible with your current set-up and/or need some tweaking before running

Credits and acknowledgements:

- [Brendan Gregg](https://twitter.com/brendangregg) for writing many of the example tools/scripts for bcc which have been used as guide for writing the scripts in this folder
- BPF and [bcc](https://github.com/iovisor/bcc) development teams
- [Frits Hoogland](https://twitter.com/fritshoogland) for collaboration on investigating Oracle internals and userspace tracing.
- [Sasha Goldshtein](https://twitter.com/goldshtn) has developed scripts for bcc tracing of MySQL and PostgreSQL, see for example [dbstat.py](https://github.com/iovisor/bcc/blob/master/tools/dbstat.py)
- [Hatem Mahmoud](https://twitter.com/Hatem__Mahmoud) has investigated the issue with uprobes and Oracle 12c and higher, providing a simple workaround
