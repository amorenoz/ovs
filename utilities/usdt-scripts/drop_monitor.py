#!/usr/bin/env python3
#
# Copyright (c) 2023 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Script information:
# -------------------
#  usage: drop_monitor.py [-h] [--buffer-page-count NUMBER] [-D [DEBUG]]
#                         [-r FILE] [-w FILE] [-P PAHOLE] [-p [64-2048]]
#                         [-s EVENTS] [--print]
#
#  Capture packets dropped by OVS and optionally write them into a pcapng file
#  for later analysis.
#
#  options:
#    -h, --help            show this help message and exit
#    --buffer-page-count NUMBER
#                          Number of BPF ring buffer pages, default 1024
#    -D [DEBUG], --debug [DEBUG]
#                          Enable eBPF debugging
#    -r FILE, --read-events FILE
#                          Read events from <FILE> instead of installing
#                          tracepoints
#    -w FILE, --write-events FILE
#                          Write events in pcapng format at <FILE>
#    -P PAHOLE, --pahole PAHOLE
#                          Pahole executable to use, default pahole
#    -p [64-2048], --packet-size [64-2048]
#                          Set maximum packet size to capture, default 256
#    -s EVENTS, --stop EVENTS
#                          Stop after receiving EVENTS number of trace events
#    --print               Print events even if '--write-events' has been used

try:
    from bcc import BPF
except ModuleNotFoundError:
    print("WARNING: Can't find the BPF Compiler Collection (BCC) tools!")
    print("         This is NOT problem if you analyzing previously collected"
          " data.\n")

import argparse
from ctypes import c_int32
import re
import subprocess
import sys
import time

from scapy.layers.l2 import Ether
from scapy.utils import PcapNgWriter, PcapNgReader

DEFAULT_KFREE_SKB_REAONS = ["SKB_DROP_REASON_PKT_TOO_BIG",
                            "SKB_DROP_REASON_NOMEM"]

#
# Actual eBPF source code
#
EBPF_SOURCE = """
#include <linux/skbuff.h>

#define MAX_PACKET <MAX_PACKET_VAL>

#define barrier_var(var) asm volatile("" : "=r"(var) : "0"(var))

enum ovs_extra_drop_reason {
    OVS_UPCALL_DROP = 1,
};

struct event_t {
    u64 ts;
    u32 reason;
    u32 extra_reason;
    u32 pkt_size;
    u32 pkt_frag_size;
    unsigned char pkt[MAX_PACKET];
};


BPF_RINGBUF_OUTPUT(events, <BUFFER_PAGE_CNT>);
BPF_PERCPU_HASH(dropcnt, u32, u64);
BPF_PERCPU_HASH(extradropcnt, u32, u64);
BPF_HASH(monitor_reasons, u32, u32);
BPF_HASH(upcalls, u64, struct sk_buff *);


static inline
int fill_event(struct event_t *event, struct sk_buff *skb) {
    u64 size;
    u32 mac;

    if (!skb) {
        return -1;
    }

    mac = skb->mac_header;
    if (!mac) {
        return -1;
    }

    event->pkt_size = skb->len - (skb->head + skb->mac_header - skb->data);

    if (skb->data_len != 0) {
        event->pkt_frag_size = (skb->len - skb->data_len) & 0xfffffff;
        size = event->pkt_frag_size;
    } else {
        event->pkt_frag_size = 0;
        size = event->pkt_size;
    }

    /* Prevent clang from using register mirroring (or any optimization) on
     * the 'size' variable. */
    barrier_var(size);
    if (size > MAX_PACKET)
        size = MAX_PACKET;

    bpf_probe_read_kernel(event->pkt, size, skb->head  + skb->mac_header);
    return 0;
}

TRACEPOINT_PROBE(openvswitch, ovs_dp_upcall) {
    u64 tid = bpf_get_current_pid_tgid();
    struct sk_buff *skb = args->skbaddr;

    upcalls.update(&tid, &skb);
}

int kretprobe__ovs_dp_upcall(struct pt_regs *ctx) {
    u64 tid = bpf_get_current_pid_tgid();
    struct sk_buff **skb;
    u32 reason = OVS_UPCALL_DROP;
    int ret = PT_REGS_RC(ctx);

    if (!ret) {
        return 0;
    }

    skb = upcalls.lookup(&tid);
    if (!skb) {
        extradropcnt.increment(reason);
        return -1;
    }
    upcalls.delete(&tid);

    struct event_t *event =
        events.ringbuf_reserve(sizeof(struct event_t));

    if (!event) {
        extradropcnt.increment(reason);
        return -1;
    }

    event->extra_reason = reason;
    event->ts = bpf_ktime_get_ns();

    if (fill_event(event, *skb)) {
        events.ringbuf_discard(event, 0);
        return 1;
    }

    events.ringbuf_submit(event, 0);
    return 0;
}

TRACEPOINT_PROBE(skb, kfree_skb) {
    struct sk_buff *skb = args->skbaddr;
    u32 reason = args->reason;

    if (!monitor_reasons.lookup(&reason)) {
        return 0;
    }

    struct event_t *event =
        events.ringbuf_reserve(sizeof(struct event_t));

    if (!event) {
        dropcnt.increment(reason);
        return -1;
    }

    event->reason = reason;
    event->ts = bpf_ktime_get_ns();

    if (fill_event(event, skb)) {
        events.ringbuf_discard(event, 0);
        return 1;
    }

    events.ringbuf_submit(event, 0);
    return 0;
}
"""


#
# get_drop_reasons
#
def get_skb_drop_reasons(pahole="pahole"):
    """"Extract drop_reason enums values from available BTF information."""
    vmlinux = "/sys/kernel/btf/vmlinux"
    openvswitch = "/sys/kernel/btf/openvswitch"

    class PaholeError(Exception):
        pass

    def run_pahole(btf_file, object_str):
        command = [pahole, "-C", object_str, btf_file]
        try:
            result = subprocess.run(command,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT,
                                    encoding='utf8',
                                    check=True).stdout

        except subprocess.CalledProcessError as perror:
            raise PaholeError(perror.stdout)

        if bool(re.search("pahole: type .* not found", result)):
            return None

        return result

    def parse_enum(enum_str):
        """Take a C enum and create return an dictionary of names and values"""
        values = {}
        if not enum_str:
            return values

        name_m = re.match(r"\s*enum (\w+)\s*{", enum_str)
        if not name_m or not len(name_m.groups()) == 1:
            return values

        value_re = re.compile(r"\s*(\w+)\s*=\s*(\d+)")
        for line in enum_str.split('\n'):
            value_m = value_re.match(line)
            if not value_m or len(value_m.groups()) != 2:
                continue
            values[int(value_m.group(2))] = value_m.group(1)

        return values

    try:
        kfree_skb_reason = parse_enum(run_pahole(vmlinux, "skb_drop_reason"))
    except PaholeError as err:
        print(f"ERROR: Cannot extract skb drop reasons {err}")
        sys.exit(-1)

    try:
        ovs_drop_reason = parse_enum(run_pahole(openvswitch,
                                                   "ovs_drop_reason"))
    except PaholeError as err:
        print(f"ERROR: Cannot extract skb drop reasons {err}")
        sys.exit(-1)

    return kfree_skb_reason, ovs_drop_reason


#
# buffer_size_type()
#
def buffer_size_type(astr, min=64, max=2048):
    value = int(astr)
    if min <= value <= max:
        return value
    else:
        raise argparse.ArgumentTypeError(
            'value not in range {}-{}'.format(min, max))


#
# EventProcessor
#
class EventProcessor:
    def __new__(cls, *args, **kwargs):
        if not hasattr(cls, 'instance'):
            cls.instance = super(EventProcessor, cls).__new__(cls)
        return cls.instance

    def __init__(self, options):
        self.n_received = 0
        self.options = options
        self.kfree_drop_reasons, self.ovs_drop_reasons = get_skb_drop_reasons(
            options.pahole)

        if options.read_events:
            self.process_events_from_file(options.read_events)
            sys.exit(0)

        if options.write_events:
            self.writer = PcapNgWriter(options.write_events)

        self.init_time()
        source = EBPF_SOURCE.replace("<MAX_PACKET_VAL>",
                                     str(options.packet_size))
        source = source.replace("<BUFFER_PAGE_CNT>",
                                str(options.buffer_page_count))

        self.b = BPF(text=source, debug=options.debug & 0xffffff)

        print("- Capturing events [Press ^C to stop]...")
        self.b['events'].open_ring_buffer(self.receive_event_bcc)

        #
        # Populate reasons we're interested in.
        #
        reasons = self.b.get_table('monitor_reasons')
        zero = c_int32(0)
        for reason in self.ovs_drop_reasons:
            reasons[c_int32(reason)] = zero

        for name in DEFAULT_KFREE_SKB_REAONS:
            val = self.get_reason_value(name)
            if val:
                reasons[c_int32(val)] = zero

    def get_reason_value(self, name):
        def key_from_val(d, val):
            try:
                return list(d.keys())[list(d.values()).index(val)]
            except ValueError:
                return None

        reason = key_from_val(self.ovs_drop_reasons, name)
        if not reason:
            reason = key_from_val(self.kfree_drop_reasons, name)
        return reason

    def get_reason(self, event):
        if event.extra_reason == 1:  # UPCALL_DROP
            return "OVS_DROP_REASON_UPCALL"

        return self.ovs_drop_reasons.get(event.reason,
                                         self.kfree_drop_reasons.get(
                                             event.reason, "UNKNOWN"))

    def process_events_from_file(self, path):
        try:
            with PcapNgReader(path) as r:
                print("- Reading events from \"{}\"...".format(path))
                self.print_header()
                while True:
                    pkt = r.read_packet()
                    reason = self.read_comment(pkt)

                    print("{:<30} {}".format(reason, pkt.summary()))
        except EOFError:
            pass

    @classmethod
    def receive_event_bcc(cls, ctx, data, size):
        event = cls.instance.b['events'].event(data)

        cls.instance.receive(event)

    def receive(self, event):
        self.n_received += 1
        if event.pkt_frag_size != 0:
            pkt_len = event.pkt_frag_size
        else:
            pkt_len = event.pkt_size

        cap_len = min(pkt_len, self.options.packet_size)

        pkt = Ether(bytes(event.pkt)[:cap_len])
        reason = self.get_reason(event)

        if self.options.write_events:
            secs = self.get_time(event.ts)
            pkt.comment = self.get_comment(reason)
            pkt.time = secs

            self.writer.write_header(pkt)
            self.writer.write_packet(
                pkt,
                sec=secs,
                caplen=cap_len,
                wirelen=pkt_len)

        if not self.options.write_events or self.options.print:
            print("{:<30} {}".format(reason, pkt.summary()))
        else:
            print(f"- Captured {self.n_received} packets", end='\r')

    def start(self):
        print("- Compiling eBPF programs...")
        if not self.options.write_events or self.options.print:
            self.print_header()
        else:
            print(f"- Captured {self.n_received} packets", end='\r')

        while 1:
            try:
                self.b.ring_buffer_poll()
                if self.options.stop != 0 and \
                        self.n_received >= self.options.stop:
                    break
            except KeyboardInterrupt:
                break

        if self.options.write_events:
            self.writer.flush()
            self.writer.close()

    def init_time(self):
        """BPF events contain a ns timestamp since the boot time but we cannot
        know when the system booted. So store the current time and current
        value of the MONOTONIC_CLOCK so we can estimate the time of the drop by
        offsetting all timestamps by the same value.
        The resulting times will all be slightly innacurate but their
        delta should not."""
        self.init_ts = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        self.init_ns = time.time_ns()

    def get_time(self, timestamp):
        """Return the corrected (float) seconds from epoch."""
        return (self.init_ns + (timestamp - self.init_ts)) / 1000000000

    @classmethod
    def get_comment(cls, reason):
        return f"DROP_REASON={reason}"

    @classmethod
    def read_comment(cls, pkt):
        comment = pkt.comment.decode().split("=")
        return comment[1] if len(comment) == 2 else None

    @classmethod
    def print_header(cls):
        print("{:<30} {:<10}".format("REASON", "PACKET"))


#
# main()
#
def main():
    global b
    global event_processor
    #
    # Argument parsing
    #
    parser = argparse.ArgumentParser(description="Capture packets dropped by "
                                     "OVS and optionally write them into a "
                                     "pcapng file for later analysis.")

    parser.add_argument("--buffer-page-count",
                        help="Number of BPF ring buffer pages, default 1024",
                        type=int, default=1024, metavar="NUMBER")
    parser.add_argument("-D", "--debug",
                        help="Enable eBPF debugging",
                        type=int, const=0x3f, default=0, nargs='?')
    parser.add_argument("-r", "--read-events",
                        help="Read events from <FILE> instead of installing "
                        "tracepoints", type=str, default=None, metavar="FILE")
    parser.add_argument("-w", "--write-events",
                        help="Write events in pcapng format at <FILE>",
                        type=str, default=None, metavar="FILE")
    parser.add_argument("-P", "--pahole", metavar="PAHOLE",
                        help="Pahole executable to use, default pahole",
                        type=str, default="pahole")
    parser.add_argument("-p", "--packet-size",
                        help="Set maximum packet size to capture, "
                        "default 256", type=buffer_size_type, default=256,
                        metavar="[64-2048]")
    parser.add_argument("-s", "--stop",
                        help="Stop after receiving EVENTS number of trace "
                        "events",
                        type=int, default=0, metavar="EVENTS")
    parser.add_argument("--print",
                        help="Print events even if '--write-events' has been "
                        "used", action="store_true")

    options = parser.parse_args()

    event_processor = EventProcessor(options)
    event_processor.start()


#
# Start main() as the default entry point...
#
if __name__ == '__main__':
    main()
