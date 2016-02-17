#
# Copyright(C) 2016 Linaro Limited. All rights reserved.
# Author: Tor Jeremiassen <tor.jeremiassen@linaro.org>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 as published by
# the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program.  If not, see <http://www.gnu.org/licenses/>.
#

import os
import sys

#sys.path.append(os.environ['PERF_EXEC_PATH'] + \
sys.path.append(	'/data/sysmodel_sdo/user/tor/linaro/merge/tools/perf/scripts/python/Perf-Trace-Util/lib/Perf/Trace')

from perf_trace_context import *
from subprocess import *
from Core import *
import re;

build_ids = dict();
mmaps = dict();
disasm_cache = dict();
disasm_exec = "aarch64-linux-objdump"
disasm_re = re.compile("^\s*([0-9a-fA-F]+):")

cache_size = 16*1024
cache_hits = 0
cache_misses = 0
cache_flushes = 0

def trace_begin():
        cmdstr = os.environ['PERF_EXEC_PATH'] + "perf"
        cmd_output = check_output([cmdstr, "buildid-list"]).split('\n');
        bid_re = re.compile("([a-fA-f0-9]+)[ \t]([^ \n]+)")
        for line in cmd_output:
                m = bid_re.search(line)
                if (m != None) :
                        build_ids[m.group(2)] = "/home/tor/.debug/" + m.group(2) + "/" + m.group(1);

        if ("[kernel.kallsyms]" in build_ids):
                build_ids['[kernel.kallsyms]'] = "./vmlinux"

        mmap_re = re.compile("PERF_RECORD_MMAP2 -?[0-9]+/[0-9]+: \[(0x[0-9a-fA-F]+).*:\s.*\s(.*.so)")
        cmd_output= check_output([cmdstr, "script", "--show-mmap-events"]).split('\n')
        for line in cmd_output:
                m = mmap_re.search(line)
                if (m != None) :
                        mmaps[m.group(2)] = int(m.group(1),0)



def trace_end():
        global cache_hits
        global cache_misses
        global cache_flushes
        print "cache hits: ", cache_hits, "cache misses: ", cache_misses, "cache flushes: ", cache_flushes
        pass

def process_event(t):
        global cache_hits
        global cache_misses
        global cache_flushes
        global cache_size
        global disasm_exec

        sample = t['sample']
        dso = t['dso']

        if (len(disasm_cache) > 16*1024):
                disasm_cache.clear();
                cache_flushes += 1

        addr_range = format(sample['ip'],"x")  + ":" + format(sample['addr'],"x");
        try:
                disasm_output = disasm_cache[addr_range];
                cache_hits += 1
        except:
                try:
                        fname = build_ids[dso];
                except KeyError:
                        fname = dso;

                if (dso in mmaps):
                        offset = mmaps[dso];
                        disasm = [disasm_exec,"-D","-z", "--adjust-vma="+format(offset,"#x"),"--start-address="+format(sample['ip'],"#x"),"--stop-address="+format(sample['addr'],"#x"), fname]
                else:
                        offset = 0
                        disasm = [disasm_exec,"-D","-z", "--start-address="+format(sample['ip'],"#x"),"--stop-address="+format(sample['addr'],"#x"),fname] 

                disasm_output = check_output(disasm).split('\n')
                disasm_cache[addr_range] = disasm_output;
                cache_misses += 1

        for line in disasm_output:
                m = disasm_re.search(line)
                if (m != None) :
                        print "\t",line
                else:
                        continue;

def trace_unhandled(event_name, context, event_fields_dict):
		print ' '.join(['%s=%s'%(k,str(v))for k,v in sorted(event_fields_dict.items())])

def print_header(event_name, cpu, secs, nsecs, pid, comm):
        print "print_header"
	print "%-20s %5u %05u.%09u %8u %-20s " % \
	(event_name, cpu, secs, nsecs, pid, comm),
