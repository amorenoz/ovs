/*
 * Copyright (c) 2024 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>

#include <linux/psample.h>

#include "dp-packet.h"
#include "util.h"
#include "netlink.h"
#include "netlink-socket.h"
#include "openvswitch/flow_sample.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/types.h"
#include "openvswitch/uuid.h"


struct sample {
    struct dp_packet packet;
    uint32_t group_id;
    uint32_t group_id_seq;
};

static int
parse_psample(struct ofpbuf *buf, struct sample *sample) {
    static const struct nl_policy psample_packet_policy[] = {
        [PSAMPLE_ATTR_SAMPLE_GROUP] = { .type = NL_A_U32 },
        [PSAMPLE_ATTR_DATA] = { .type = NL_A_UNSPEC },
    };

    struct ofpbuf b = ofpbuf_const_initializer(buf->data, buf->size);
    struct nlmsghdr *nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    struct genlmsghdr *genl = ofpbuf_try_pull(&b, sizeof *genl);

    struct nlattr *a[ARRAY_SIZE(psample_packet_policy)];
    if (!nlmsg || !genl
        || !nl_policy_parse(&b, 0, psample_packet_policy, a,
                            ARRAY_SIZE(psample_packet_policy))) {
        return EINVAL;
    }

    dp_packet_use_stub(&sample->packet,
                       CONST_CAST(struct nlattr *,
                                  nl_attr_get(a[PSAMPLE_ATTR_DATA])) - 1,
                       nl_attr_get_size(a[PSAMPLE_ATTR_DATA]) +
                          sizeof(struct nlattr));
    dp_packet_set_data(&sample->packet,
                       (char *)dp_packet_data(&sample->packet) +
                           sizeof(struct nlattr));
    dp_packet_set_size(&sample->packet,
                       nl_attr_get_size(a[PSAMPLE_ATTR_DATA]));

    sample->group_id = nl_attr_get_u32(a[PSAMPLE_ATTR_SAMPLE_GROUP]);
    return 0;
}


static void usage(void)
{
    fprintf(stdout, "ovs-sample");
}

int
main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    unsigned int psample_packet_mcgroup;
    struct nl_sock *sock;
    int psample_family;
    int error;

    if (argc > 1) {
        usage();
        return EINVAL;
    }

    error = nl_lookup_genl_family(PSAMPLE_GENL_NAME , &psample_family);
    if (error)
        ovs_fatal(0, "PSAMPLE_GENL_NAME not found: %i", error);

    error = nl_lookup_genl_mcgroup(PSAMPLE_GENL_NAME,
                                   PSAMPLE_NL_MCGRP_SAMPLE_NAME,
                                   &psample_packet_mcgroup);
    if (error)
        ovs_fatal(0, "psample packet multicast group not found: %i", error);

    error = nl_sock_create(NETLINK_GENERIC, &sock);
    if (error)
        ovs_fatal(0, "cannot create netlink socket: %i ", error);

    nl_sock_listen_all_nsid(sock, true);

    error = nl_sock_join_mcgroup(sock, psample_packet_mcgroup);
    if (error) {
        nl_sock_destroy(sock);
        ovs_fatal(0, "cannot join psample multicast group: %i", error);
    }

    for (;;) {
        uint64_t buf_stub[4096 / 8];
        struct ofpbuf buf;
        struct sample sample = {};

        ofpbuf_use_stub(&buf, buf_stub, sizeof buf_stub);
        error = nl_sock_recv(sock, &buf, NULL, true);

        if (error == ENOBUFS) {
            fprintf(stderr, "missed events\n");
            continue;
        } else if (error == EAGAIN) {
            continue;
        } else if (error) {
            ovs_fatal(0, "error reading samples: %i", error);
        }

        error = parse_psample(&buf, &sample);
        if (error)
            ovs_fatal(0, "error parsing sample %i", error);

        fprintf(stdout, "group_id = 0x%"PRIx32": ",
                sample.group_id);
        ofp_print_dp_packet(stdout, &sample.packet);
    }
}
