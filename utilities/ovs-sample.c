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

#include "dp-packet.h"
#include "util.h"
#include "netlink.h"
#include "netlink-socket.h"
#include "odp-util.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/types.h"
#include "openvswitch/uuid.h"

static int ovs_packet_family;
static unsigned int ovs_packet_mcgroup;

struct sample {
    struct dp_packet packet;
    const struct nlattr *key;      /* Datapath flow key. */
    size_t key_len;                /* Datapath flow key length. */

    struct nlattr *actions;
    struct nlattr *hash;
    uint32_t collector_set_id;
    uint32_t obs_domain_id;
    uint32_t obs_point_id;
};

static int
parse_raw_sample(struct ofpbuf *buf, struct sample *sample) {
    struct user_action_cookie cookie = {};

    static const struct nl_policy ovs_packet_policy[] = {
        /* Always present. */
        [OVS_PACKET_ATTR_PACKET] = { .type = NL_A_UNSPEC,
                                     .min_len = ETH_HEADER_LEN },
        [OVS_PACKET_ATTR_KEY] = { .type = NL_A_NESTED },

        /* OVS_PACKET_CMD_ACTION only. */
        [OVS_PACKET_ATTR_USERDATA] = { .type = NL_A_UNSPEC, .optional = true },
        [OVS_PACKET_ATTR_EGRESS_TUN_KEY] = { .type = NL_A_NESTED, .optional = true },
        [OVS_PACKET_ATTR_ACTIONS] = { .type = NL_A_NESTED, .optional = true },
        [OVS_PACKET_ATTR_MRU] = { .type = NL_A_U16, .optional = true },
        [OVS_PACKET_ATTR_HASH] = { .type = NL_A_U64, .optional = true }
    };

    struct ofpbuf b = ofpbuf_const_initializer(buf->data, buf->size);
    struct nlmsghdr *nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    struct genlmsghdr *genl = ofpbuf_try_pull(&b, sizeof *genl);
    struct ovs_header *ovs_header = ofpbuf_try_pull(&b, sizeof *ovs_header);

    struct nlattr *a[ARRAY_SIZE(ovs_packet_policy)];
    if (!nlmsg || !genl || !ovs_header
        || nlmsg->nlmsg_type != ovs_packet_family
        || !nl_policy_parse(&b, 0, ovs_packet_policy, a,
                            ARRAY_SIZE(ovs_packet_policy))) {
        return EINVAL;
    }

    if (genl->cmd != OVS_PACKET_CMD_ACTION) {
        fprintf(stderr, "unexpected cmd type\n");
        return EINVAL;
    }

    sample->key = CONST_CAST(struct nlattr *,
                             nl_attr_get(a[OVS_PACKET_ATTR_KEY]));
    sample->key_len = nl_attr_get_size(a[OVS_PACKET_ATTR_KEY]);
    sample->actions = a[OVS_PACKET_ATTR_ACTIONS];
    sample->hash = a[OVS_PACKET_ATTR_HASH];

    dp_packet_use_stub(&sample->packet,
                       CONST_CAST(struct nlattr *,
                                  nl_attr_get(a[OVS_PACKET_ATTR_PACKET])) - 1,
                                  nl_attr_get_size(a[OVS_PACKET_ATTR_PACKET]) +
                                  sizeof(struct nlattr));

    dp_packet_set_data(&sample->packet,
        (char *)dp_packet_data(&sample->packet) + sizeof(struct nlattr));
    dp_packet_set_size(&sample->packet, nl_attr_get_size(a[OVS_PACKET_ATTR_PACKET]));

    if (nl_attr_find__(sample->key, sample->key_len, OVS_KEY_ATTR_ETHERNET)) {
        /* Ethernet frame */
        sample->packet.packet_type = htonl(PT_ETH);
    } else {
        /* Non-Ethernet packet. Get the Ethertype from the NL attributes */
        ovs_be16 ethertype = 0;
        const struct nlattr *et_nla = nl_attr_find__(sample->key,
                                                     sample->key_len,
                                                     OVS_KEY_ATTR_ETHERTYPE);
        if (et_nla) {
            ethertype = nl_attr_get_be16(et_nla);
        }
        sample->packet.packet_type = PACKET_TYPE_BE(OFPHTN_ETHERTYPE,
                                                    ntohs(ethertype));
        dp_packet_set_l3(&sample->packet, dp_packet_data(&sample->packet));
    }

    struct nlattr *userdata = a[OVS_PACKET_ATTR_USERDATA];
    size_t userdata_len = nl_attr_get_size(userdata);

    if (userdata_len != sizeof cookie) {
        fprintf(stderr, "action upcall cookie has unexpected size %"PRIuSIZE,
                userdata_len);
        return EINVAL;
    }
    memcpy(&cookie, nl_attr_get(userdata), sizeof cookie);

    if (cookie.type != USER_ACTION_COOKIE_FLOW_SAMPLE) {
        fprintf(stderr, "action upcall cookie has unexpected type %"PRIu16,
                cookie.type);
        return EINVAL;
    }

    sample->collector_set_id = cookie.flow_sample.collector_set_id;
    sample->obs_domain_id = cookie.flow_sample.obs_domain_id;
    sample->obs_point_id = cookie.flow_sample.obs_point_id;

    return 0;
}


int
main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct nl_sock *sock;
    int error;

    error = nl_lookup_genl_family(OVS_PACKET_FAMILY, &ovs_packet_family);
    if (error)
        ovs_fatal(0, "OVS_PACKET_FAMILY not found: %i", error);

    error = nl_lookup_genl_mcgroup(OVS_PACKET_FAMILY, OVS_PACKET_MCGROUP,
                                   &ovs_packet_mcgroup);
    if (error)
        ovs_fatal(0, "packet multicast group not found: %i", error);

    error = nl_sock_create(NETLINK_GENERIC, &sock);
    if (error)
        ovs_fatal(0, "cannot create netlink socket: %i ", error);

    error = nl_sock_join_mcgroup(sock, ovs_packet_mcgroup);
    if (error) {
        nl_sock_destroy(sock);
        ovs_fatal(0, "cannot register to multicast group: %i", error);
    }

    for (;;) {
        uint64_t buf_stub[4096 / 8];
        struct ofpbuf buf;
        struct sample sample = {};

        ofpbuf_use_stub(&buf, buf_stub, sizeof buf_stub);
        error = nl_sock_recv(sock, &buf, NULL, false);

        if (error == ENOBUFS) {
            fprintf(stderr, "missed events\n");
            continue;
        }
        if (error) {
            if (error == EAGAIN) {
                continue;
            }
            ovs_fatal(0, "error reading samples: %i", error);
        }

        error = parse_raw_sample(&buf, &sample);
        if (error)
            ovs_fatal(0, "error parsing sample %i", error);

        ofp_print_dp_packet(stdout, &sample.packet);
        fprintf(stdout, "\_  obs_point = 0x%"PRIx32" obs_domain = 0x%"PRIx32
                "\n\n", sample.obs_point_id, sample.obs_domain_id);
    }
    return 0;
}
