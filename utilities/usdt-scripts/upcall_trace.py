#!/usr/bin/env python3
#
# Copyright (c) 2024 Red Hat, Inc.
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
# TBD

try:
    from bcc import BPF, USDT, USDTException
except ModuleNotFoundError:
    print("WARNING: Can't find the BPF Compiler Collection (BCC) tools!")
    print(
        "         This is NOT problem if you analyzing previously collected"
        " data.\n"
    )

import argparse
import ctypes
import psutil
import re
import sys
import time

from ipaddress import IPv4Network, IPv4Address

#
# Actual eBPF source code
#
ebpf_source = """
#include <linux/skbuff.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/openvswitch.h>
#include <uapi/linux/netlink.h>

/* Minimum set of netlink helpers. */

#define NLA_F_NESTED      (1 << 15)
#define NLA_F_NET_BYTEORDER   (1 << 14)
#define NLA_TYPE_MASK      ~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)

#define NLA_ALIGNTO      4
#define NLA_ALIGN(len)      (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#define NLA_HDRLEN      ((int) NLA_ALIGN(sizeof(struct nlattr)))

/**
 * nla_type - attribute type
 * @nla: netlink attribute
 */
static __always_inline int nla_type(const struct nlattr *nla)
{
    return nla->nla_type & NLA_TYPE_MASK;
}

/**
 * nla_data - head of payload
 * @nla: netlink attribute
 */
static __always_inline void *nla_data(const struct nlattr *nla)
{
    return (char *) nla + NLA_HDRLEN;
}

/**
 * nla_len - length of payload
 * @nla: netlink attribute
 */
static __always_inline int nla_len(const struct nlattr *nla)
{
    return nla->nla_len - NLA_HDRLEN;
}

/**
 * nla_next - next netlink attribute in attribute stream
 * @nla: netlink attribute
 * @remaining: number of bytes remaining in attribute stream
 *
 * Returns the next netlink attribute in the attribute stream and
 * decrements remaining by the size of the current attribute.
 */
static inline struct nlattr *nla_next(const struct nlattr *nla, int *remaining)
{
   u16 nla_len;
   bpf_probe_read_user(&nla_len, sizeof(nla_len), &nla->nla_len);

   int totlen = NLA_ALIGN(nla_len);

   *remaining -= totlen;
   return (struct nlattr *) ((char *) nla + totlen);
}

static inline bool
ternary_match(u8 *p1, u8 *p2, u8 *pm, int sz) {
   for (; sz > 0; sz--) {
      if (*pm && (*p1 & *pm) != *p2)
         return false;
      p1++, p2++, pm++;
   }
   return true;
}

typedef union {
    u32 u32[4];
    struct {
        u64 lo, hi;
    } u64;
} ovs_u128;

enum event_type {
    UPCALL_START = 0,
    UPCALL_XLATE = 1,
    UPCALL_OP_PUT = 2,
    UPCALL_OP_EXEC = 3,
};


struct packet_data {
    u8 eth_src[ETH_ALEN];
    u8 eth_dst[ETH_ALEN];
    __be32 ipv4_src;
    __be32 ipv4_dst;
    u8 ip_proto;
    __be16 tp_src;
    __be16 tp_dst;
};

struct filter {
    struct packet_data value;
    struct packet_data mask;
};

#define MAX_ACTIONS 1024

struct event_t {
    enum event_type type;
    u64 upcall_id;
    union {
        struct packet_data packet;
        struct {
            u8 table_id;
            u64 cookie;
            u8 acts[MAX_ACTIONS]
            // TODO: Add ofpacts
        } xlate;
        ovs_u128 ufid;
    } data;
};

BPF_ARRAY(filter_map, struct filter, 1);

static __always_inline
bool filter_keys(struct nlattr *ap, uint64_t size, struct packet_data *data) {
    int rem = size & 0xFFFFFFFF;
    struct filter *filter;
    struct nlattr a = {};
    int i, zero = 0;

    filter = filter_map.lookup(&zero);
    if (!filter)
        return false;

    for (i = 0; i < 20; i++) {
        if (!ap || bpf_probe_read_user(&a, sizeof(a), ap))
            break;

        switch(a.nla_type & NLA_TYPE_MASK) {
        case OVS_KEY_ATTR_ETHERNET:
        {
            struct ovs_key_ethernet ethernet = {};
            bpf_probe_read_user(&ethernet, sizeof(ethernet), nla_data(ap));

            __builtin_memcpy(&data->eth_src, &ethernet.eth_src, ETH_ALEN);
            __builtin_memcpy(&data->eth_dst, &ethernet.eth_dst, ETH_ALEN);
            break;
        }
        case OVS_KEY_ATTR_IPV4:
        {
            struct ovs_key_ipv4 ipv4 = {};
            bpf_probe_read_user(&ipv4, sizeof(ipv4), nla_data(ap));

            data->ipv4_src = ipv4.ipv4_src;
            data->ipv4_dst = ipv4.ipv4_dst;
            data->ip_proto = ipv4.ipv4_proto;
            break;
        }
        case OVS_KEY_ATTR_TCP:
        {
            struct ovs_key_tcp tcp = {};
            bpf_probe_read_user(&tcp, sizeof(tcp), nla_data(ap));
            bpf_trace_printk("TCP");

            data->tp_src = tcp.tcp_src;
            data->tp_dst = tcp.tcp_dst;
            break;
        }
        case OVS_KEY_ATTR_UDP:
        {
            struct ovs_key_udp udp = {};
            bpf_probe_read_user(&udp, sizeof(udp), nla_data(ap));
            bpf_trace_printk("UDP");

            data->tp_src = udp.udp_src;
            data->tp_dst = udp.udp_dst;
            break;
        }
        }

        /* Prepare for next iteration. */
        rem -= NLA_ALIGN(a.nla_len);
        ap = (struct nlattr *) ((char *) ap + NLA_ALIGN(a.nla_len));
        if (rem <= 0)
            break;
    }

    bpf_trace_printk("tp_src %d %d %d", data->tp_src, filter->value.tp_src,
    filter->mask.tp_src);
    return ternary_match((u8 *)data, (u8 *)&filter->value, (u8 *)&filter->mask,
                         sizeof(struct packet_data));
}

struct upcall {
    struct packet_data packet;
    u64 id;
};

BPF_HASH(xlate_upcalls, u64, struct upcall, 1024);
BPF_HASH(handle_upcalls, ovs_u128, u64, 1024);
BPF_RINGBUF_OUTPUT(events, 8);

int trace__dpif_upcall_op_exec(struct pt_regs *ctx)
{
    struct event_t event = {};
    ovs_u128 ufid = {};
    u64 *upcall_id;

    bpf_usdt_readarg_p(6, ctx, &ufid, sizeof(ufid));

    upcall_id = handle_upcalls.lookup(&ufid);
    if (!upcall_id)
        return 0;

    event.type = UPCALL_OP_EXEC;
    event.upcall_id = *upcall_id;
    events.ringbuf_output(&event, sizeof(event), 0);
    return 0;
}

int trace__dpif_upcall_op_put(struct pt_regs *ctx)
{
    struct event_t event = {};
    ovs_u128 ufid = {};
    u64 *upcall_id;

    bpf_usdt_readarg_p(8, ctx, &ufid, sizeof(ufid));

    upcall_id = handle_upcalls.lookup(&ufid);
    if (!upcall_id)
        return 0;

    event.type = UPCALL_OP_PUT;
    event.upcall_id = *upcall_id;
    events.ringbuf_output(&event, sizeof(event), 0);
    return 0;
}

int trace__xlate_do_xlate_actions(struct pt_regs *ctx)
{
    u64 pid = bpf_get_current_pid_tgid();
    struct event_t event = {};
    struct upcall *upcall;
    u64 *cookie;
    u64 size;
    u8 *acts;

    upcall = xlate_upcalls.lookup(&pid);
    if (!upcall)
        return 0;

    __builtin_memcpy(&event.data.packet, &upcall->packet,
                     sizeof(event.data.packet));
    bpf_usdt_readarg(5, ctx, &event.data.xlate.table_id);
    bpf_usdt_readarg(6, ctx, &cookie);

    bpf_usdt_readarg(2, ctx, &size);
    bpf_usdt_readarg(1, ctx, &acts);
    if (acts) {
        if (size >= MAX_ACTIONS)
            size = MAX_ACTIONS
        bpf_probe_read_user(&event.data.xlate.acts, size, acts);
    }

    bpf_probe_read_user((u8*) &event.data.xlate.cookie, 8, (u8*) cookie);
    bpf_trace_printk("cookie %lx", event.data.xlate.cookie);
    event.type = UPCALL_XLATE;
    event.upcall_id = upcall->id;
    events.ringbuf_output(&event, sizeof(event), 0);
}

int trace__upcall_xlate_end(struct pt_regs *ctx)
{
    u64 pid = bpf_get_current_pid_tgid();
    struct upcall *upcall;
    ovs_u128 ufid;

    bpf_usdt_readarg_p(4, ctx, &ufid, sizeof(ufid));

    upcall = xlate_upcalls.lookup(&pid);
    if (!upcall)
        return 0;

    handle_upcalls.update(&ufid, &upcall->id);
    xlate_upcalls.delete(&pid);
}

BPF_PERCPU_ARRAY(next_id, u32, 1);
int trace__upcall_xlate_start(struct pt_regs *ctx)
{
    struct upcall upcall = {};
    struct event_t event = {};
    struct nlattr *a;
    u32 *id, zero = 0;
    u64 size;
    u64 pid;

    bpf_usdt_readarg(4, ctx, &a);
    bpf_usdt_readarg(5, ctx, &size);

    if (!a)
        return 0;

    if(filter_keys(a, size, &upcall.packet)) {
        pid = bpf_get_current_pid_tgid();
        id = next_id.lookup(&zero);
        if (!id)
            return 0;
        upcall.id = bpf_get_smp_processor_id() << 32 | (*id)++;
        next_id.update(&zero, id);

        xlate_upcalls.update(&pid, &upcall);

        __builtin_memcpy(&event.data.packet, &upcall.packet,
                         sizeof(upcall.packet)); id;
        event.upcall_id = upcall.id;
        event.type = UPCALL_START;
        events.ringbuf_output(&event, sizeof(event), 0);
    }

    return 0;
}

"""


FILTER_ETH = 0
FILTER_IPv4 = 1
FILTER_TCP = 2
FILTER_UDP = 3


ETH_LEN = 6


class PrintableMixin:
    def __repr__(self):
        values = ", ".join(
            "{}={}".format(name, value)
            for name, value in self._asdict().items()
        )
        return "<{}: {}>".format(self.__class__.__name__, values)

    def _asdict(self):
        return {field[0]: getattr(self, field[0]) for field in self._fields_}


# For some reason, deriving from a BE type (e.g. ctypes.c_uint32.__ctype_be__)
# does not correctly preserve endianness when bytes are casted.
# So, keeping the underlying type LE and doing the conversion manually.
class IpAddr(ctypes.c_uint32):
    def __init__(self, ipv4):
        self.value = int.from_bytes(ipv4.packed, "little")

    def ip(self):
        return IPv4Address(self.value.to_bytes(4)[::-1])

    def __repr__(self):
        return "<{}: {}>".format(self.__class__.__name__, self.ip())


class EthAddr(ctypes.c_uint8 * ETH_LEN):
    def __repr__(self):
        values = ":".join("{:02x}".format(i) for i in self)
        return "<{}: {}>".format(self.__class__.__name__, values)


class PacketData(PrintableMixin, ctypes.Structure):
    _fields_ = [
        ("eth_src", EthAddr),
        ("eth_dst", EthAddr),
        ("ipv4_src", IpAddr),
        ("ipv4_dst", IpAddr),
        ("ip_proto", ctypes.c_uint8),
        ("tp_src", ctypes.c_uint16.__ctype_be__),
        ("tp_dst", ctypes.c_uint16.__ctype_be__),
    ]


class Filter(PrintableMixin, ctypes.Structure):
    _fields_ = [("value", PacketData), ("mask", PacketData)]


class Cookie(ctypes.c_uint64):
    def __str__(self):
        return hex(int.from_bytes(self.value.to_bytes(8)[::-1]))


class XlateEventData(PrintableMixin, ctypes.Structure):
    _fields_ = [
        ("table_id", ctypes.c_uint8),
        ("cookie", Cookie),
        ("acts", ctypes.c_uint8 * 1024),
    ]


class UFID(ctypes.c_uint32 * 4):
    def __str__(self):
        return "{:08x}-{:04x}-{:04x}-{:04x}-{:04x}{:08x}".format(
            self[0],
            self[1] >> 16,
            self[1] & 0xFFFF,
            self[2] >> 16,
            self[2] & 0xFFFF,
            self[3],
        )

    def __repr__(self):
        return "<{}: {}>".format(self.__class__.__name__, str(self))


class EventData(PrintableMixin, ctypes.Union):
    _fields_ = [
        ("packet", PacketData),
        ("xlate", XlateEventData),
        ("ufid", UFID),
    ]


class UpcallId(ctypes.c_uint64):
    def __str__(self):
        return "{}/{}".format(self.value >> 32, self.value & 0xFFFFFFFF)

    def __repr__(self):
        return "<{}: {}>".format(self.__class__.__name__, str(self))


class EventType(ctypes.c_uint):
    UPCALL_START = 0
    UPCALL_XLATE = 1
    UPCALL_OP_PUT = 2
    UPCALL_OP_EXEC = 3

    def __str__(self):
        if self.value == self.UPCALL_START:
            return "UPCALL_START"
        elif self.value == self.UPCALL_XLATE:
            return "UPCALL_XLATE"
        elif self.value == self.UPCALL_OP_PUT:
            return "UPCALL_OP_PUT"
        elif self.value == self.UPCALL_OP_EXEC:
            return "UPCALL_OP_EXEC"
        else:
            return "UNDEFINED"


class Event(PrintableMixin, ctypes.Structure):
    _fields_ = [
        ("type", EventType),
        ("upcall_id", UpcallId),
        ("data", EventData),
    ]

    def __str__(self):
        if self.type.value == EventType.UPCALL_START:
            data = self.data.packet
        elif self.type.value == EventType.UPCALL_XLATE:
            data = self.data.xlate
        elif self.type.value == EventType.UPCALL_OP_PUT:
            data = ""
        elif self.type.value == EventType.UPCALL_OP_EXEC:
            data = ""

        return "{} {} {}".format(self.type, self.upcall_id, data)

    def _repr__(self):
        return "<{}: {}>".format(self.__class__.__name__, str(self))


#
# Event receiving callback
#
def event_callback(ctx, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Event)).contents
    print(event)


#
# main()
#
def main():
    global b

    #
    # Argument parsing
    #
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--src_ipv4",
        help="Filter on source IPv4 address (or subnet)",
        type=str,
        metavar="ADDRESS",
    )
    parser.add_argument(
        "--dst_ipv4",
        help="Filter on destination IPv4 address (or subnet)",
        type=str,
        metavar="ADDRESS",
    )
    parser.add_argument(
        "--src_mac",
        help="Filter on destination MAC address",
        type=str,
        metavar="ADDRESS",
    )
    parser.add_argument(
        "--dst_mac",
        help="Filter on destination IPv4 address",
        type=str,
        metavar="ADDRESS",
    )
    parser.add_argument(
        "--proto",
        help="Filter on protocol being TCP",
        choices=["tcp", "udp", "icmp"],
        metavar="PROTO",
    )
    parser.add_argument(
        "--dst_port",
        help="Filter on destination L4 port. "
        "Requires --proto to be tcp or udp.",
        type=str,
        metavar="PORT",
    )
    parser.add_argument(
        "--src_port",
        help="Filter on source L4 port. " "Requires --proto to be tcp or udp.",
        type=str,
        metavar="PORT",
    )
    parser.add_argument(
        "-p",
        "--pid",
        metavar="VSWITCHD_PID",
        help="ovs-vswitch's PID",
        type=int,
        default=None,
    )

    options = parser.parse_args()

    if options.pid is None:
        for proc in psutil.process_iter():
            if "ovs-vswitchd" in proc.name():
                if options.pid is not None:
                    print(
                        "ERROR: Multiple ovs-vswitchd daemons running, "
                        "use the -p option!"
                    )
                    sys.exit(-1)

                options.pid = proc.pid

    u = USDT(pid=int(options.pid))
    try:
        u.enable_probe(
            probe="upcall_xlate:start", fn_name="trace__upcall_xlate_start"
        )
        u.enable_probe(
            probe="upcall_xlate:end", fn_name="trace__upcall_xlate_end"
        )
        u.enable_probe(
            probe="xlate:do_xlate_actions",
            fn_name="trace__xlate_do_xlate_actions",
        )
        u.enable_probe(
            probe="dpif_upcall:put_op",
            fn_name="trace__dpif_upcall_op_put",
        )
        u.enable_probe(
            probe="dpif_upcall:exec_op",
            fn_name="trace__dpif_upcall_op_exec",
        )
    except USDTException as e:
        print(
            "ERROR: {}"
            "ovs-vswitchd!".format(
                (re.sub("^", " " * 7, str(e), flags=re.MULTILINE))
                .strip()
                .replace(
                    "--with-dtrace or --enable-dtrace", "--enable-usdt-probes"
                )
            )
        )
        sys.exit(-1)

    p_filter = Filter()

    if options.src_ipv4:
        cidr = IPv4Network(options.src_ipv4)
        p_filter.value.ipv4_src = IpAddr(cidr.network_address)
        p_filter.mask.ipv4_src = IpAddr(cidr.netmask)

    if options.dst_ipv4:
        cidr = IPv4Network(options.dst_ipv4)
        p_filter.value.ipv4_dst = IpAddr(cidr.network_address)
        p_filter.mask.ipv4_dst = IpAddr(cidr.netmask)

    if options.proto == "tcp":
        p_filter.value.ip_proto = 0x06
        p_filter.mask.ip_proto = 0xFF
    elif options.proto == "udp":
        p_filter.value.ip_proto = 0x11
        p_filter.mask.ip_proto = 0xFF
    elif options.proto == "icmp":
        p_filter.value.ip_proto = 0x01
        p_filter.mask.ip_proto = 0xFF

    if options.src_mac:
        p_filter.value.eth_src = EthAddr(
            *list(map(lambda x: int(x, 16), options.src_mac.split(":")))
        )
        p_filter.mask.eth_src = EthAddr(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
    if options.dst_mac:
        p_filter.value.eth_dst = EthAddr(
            *list(map(lambda x: int(x, 16), options.dst_mac.split(":")))
        )
        p_filter.mask.eth_dst = EthAddr(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)

    if options.src_port or options.dst_port:
        if options.proto not in ["tcp", "udp"]:
            print(
                "ERROR: TCP or UDP protocol must be specified in order"
                "to filter on the source or destination ports."
            )
            sys.exit(-1)

    if options.src_port:
        p_filter.value.tp_src = int(options.src_port)
        p_filter.mask.tp_src = 0xFFFF
    if options.dst_port:
        p_filter.value.tp_dst = int(options.dst_port)
        p_filter.mask.tp_dst = 0xFFFF

    # source = ebpf_source.replace("<FILTERS>", str(filter_bitmask))

    # b = BPF(text=ebpf_source, usdt_contexts=[u], debug=0xFFFFFFF)
    b = BPF(text=ebpf_source, usdt_contexts=[u])

    print(f"Filter: {p_filter}")

    b.get_table("filter_map")[0] = p_filter

    b["events"].open_ring_buffer(event_callback)

    try:
        while 1:
            b.ring_buffer_poll()
            time.sleep(0.5)
    except KeyboardInterrupt:
        sys.exit()


#
# Start main() as the default entry point...
#
if __name__ == "__main__":
    main()
