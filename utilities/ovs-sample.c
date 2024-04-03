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
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/types.h"
#include "openvswitch/uuid.h"

static int psample_family = 0;

struct sample {
    struct dp_packet packet;
    uint32_t group_id;
    uint32_t obs_domain_id;
    uint32_t obs_point_id;
    bool has_cookie;
};

static inline void
sample_clear(struct sample *sample) {
    sample->group_id = 0;
    sample->obs_domain_id = 0;
    sample->obs_point_id = 0;
    sample->has_cookie = false;
    dp_packet_clear(&sample->packet);
}

static int
parse_psample(struct ofpbuf *buf, struct sample *sample) {
    static const struct nl_policy psample_packet_policy[] = {
        [PSAMPLE_ATTR_SAMPLE_GROUP] = { .type = NL_A_U32 },
        [PSAMPLE_ATTR_DATA] = { .type = NL_A_UNSPEC,
                                .optional = true, },
        [PSAMPLE_ATTR_USER_COOKIE] = { .type = NL_A_UNSPEC,
                                       .optional = true },
    };

    struct ofpbuf b = ofpbuf_const_initializer(buf->data, buf->size);
    struct nlmsghdr *nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    struct genlmsghdr *genl = ofpbuf_try_pull(&b, sizeof *genl);
    struct nlattr *attr;
    const char *cookie;

    struct nlattr *a[ARRAY_SIZE(psample_packet_policy)];
    if (!nlmsg || !genl
        || !nl_policy_parse(&b, 0, psample_packet_policy, a,
                            ARRAY_SIZE(psample_packet_policy))) {
        return EINVAL;
    }

    attr = a[PSAMPLE_ATTR_DATA];
    if (attr) {
        dp_packet_push(&sample->packet, nl_attr_get(attr),
                       nl_attr_get_size(attr));
    }

    sample->group_id = nl_attr_get_u32(a[PSAMPLE_ATTR_SAMPLE_GROUP]);

    attr = a[PSAMPLE_ATTR_USER_COOKIE];
    if (attr && nl_attr_get_size(attr) == 8) {
        cookie = nl_attr_get(attr);
        sample->has_cookie = true;
        sample->obs_domain_id = (uint32_t) *(&cookie[0]);
        sample->obs_point_id = (uint32_t) *(&cookie[4]);
    }
    return 0;
}

static int _psample_set_filter(struct nl_sock *sock, uint32_t group_id,
                               bool valid)
{
        uint64_t stub[512 / 8];
        struct ofpbuf buf;
        int error;

        ofpbuf_use_stub(&buf, stub, sizeof stub);

        nl_msg_put_genlmsghdr(&buf, 0, psample_family, NLM_F_REQUEST,
                              PSAMPLE_CMD_SAMPLE_FILTER_SET, 1);
        if (valid) {
            nl_msg_put_u32(&buf, PSAMPLE_ATTR_SAMPLE_GROUP, group_id);
        }

        error = nl_sock_send(sock, &buf, false);
        if (error)
            return error;

        ofpbuf_clear(&buf);
        error = nl_sock_recv(sock, &buf, NULL, false);
        if (!error) {
            struct nlmsghdr *h = ofpbuf_at(&buf, 0, NLMSG_HDRLEN);
            if (h->nlmsg_type == NLMSG_ERROR) {
                const struct nlmsgerr *e;
                e = ofpbuf_at(&buf, NLMSG_HDRLEN,
                              NLMSG_ALIGN(sizeof(struct nlmsgerr)));
                if (!e)
                    return EINVAL;
                if (e && e->error < 0)
                    return -e->error;
            }
        } else if (error != EAGAIN) {
            return error;
        }
        return 0;
}

static inline int psample_clear_filter(struct nl_sock *sock)
{
    return _psample_set_filter(sock, 0, false);
}

static inline int psample_set_filter(struct nl_sock *sock, uint32_t group_id)
{
    return _psample_set_filter(sock, group_id, true);
}

static void usage(void)
{
    fprintf(stdout, "ovs-sample [group_id]");
}


int
main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    unsigned int psample_packet_mcgroup;
    uint32_t group_id = 0;
    struct nl_sock *sock;
    bool has_filter;
    int error;

    if (argc > 2) {
        usage();
        return EINVAL;
    } else if (argc == 2) {
        group_id = atoi(argv[1]);
        has_filter = true;
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

    if (has_filter) {
        error = psample_set_filter(sock, group_id);
        if (error)
            fprintf(stderr, "Failed to install in-kernel filter, "
                    "falling back to userspace filtering.");
    }

    error = nl_sock_join_mcgroup(sock, psample_packet_mcgroup);
    if (error) {
        nl_sock_destroy(sock);
        ovs_fatal(0, "cannot join psample multicast group: %i", error);
    }

    struct sample sample = {};
    dp_packet_init(&sample.packet, 1500);

    for (;;) {
        uint64_t buf_stub[4096 / 8];
        struct ofpbuf buf;

        sample_clear(&sample);

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

        if (!has_filter || sample.group_id == group_id) {
            fprintf(stdout, "group_id = 0x%"PRIx32": ",
                sample.group_id);
            if (sample.has_cookie) {
                fprintf(stdout,
                        "obs_domain = 0x%"PRIx32", obs_point 0x%"PRIx32" ",
                        sample.obs_domain_id, sample.obs_point_id);
            }
            ofp_print_dp_packet(stdout, &sample.packet);
        }
    }
}
