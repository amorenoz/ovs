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
#include "psample.h"

#include <linux/psample.h>
#include <linux/filter.h>

#include "netlink-protocol.h"
#include "netlink-socket.h"
#include "openvswitch/vlog.h"
#include "ovs-thread.h"
#include "socket-util.h"

VLOG_DEFINE_THIS_MODULE(psample);

static int psample_mcgroup(unsigned int *mcast_group) {
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    static unsigned int psample_packet_mcgroup = 0;
    static int psample_family = 0;

    if (ovsthread_once_start(&once)) {
        int error;

        error = nl_lookup_genl_family(PSAMPLE_GENL_NAME , &psample_family);
        if (error) {
            VLOG_ERR("PSAMPLE_GENL_NAME not found: %i. Is the module loaded?",
                     error);
        } else {
            error = nl_lookup_genl_mcgroup(PSAMPLE_GENL_NAME,
                                           PSAMPLE_NL_MCGRP_SAMPLE_NAME,
                                           &psample_packet_mcgroup);
            if (error) {
                VLOG_ERR("psample packet multicast group not found: %i",
                         error);
            }
        }
    }

    if (!psample_family || !psample_packet_mcgroup) {
        *mcast_group = 0;
        return ENOTSUP;
    }

    *mcast_group = psample_packet_mcgroup;
    return 0;
}

static struct sock_filter psample_group_filter[] = {
    /* Load sizeof(struct nlmsghdr) + sizeof(struct genlmsghdr) into A. */
    BPF_STMT(BPF_LD + BPF_IMM, sizeof(struct nlmsghdr) +
                               sizeof(struct genlmsghdr)),

    /* Load PSAMPLE_ATTR_SAMPLE_GROUP into X.*/
    BPF_STMT(BPF_LDX + BPF_IMM, PSAMPLE_ATTR_SAMPLE_GROUP),

    /* BPF Extension: Access ancillary data at offset SKF_AD_NLATTR.
     * This is equivalent to:
     *
     *   [...]
     *   nla = nla_find((struct nlattr *) &skb->data[A], skb->len - A, X);
     *   if (nla) {
     *        return (void *) nla - (void *) skb->data;
     *   }
     *   return 0;
     *
     *  The result is stored in A.
     */
    BPF_STMT(BPF_LD + BPF_ABS, SKF_AD_OFF + SKF_AD_NLATTR),

    /* Check if the value in A is zero (which means the
     * PSAMPLE_ATTR_SAMPLE_GROUP was not found), jump 4 instructions ahead,
     * returning "pass".
     */
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 4, 0),

    /* Copy A into X. */
    BPF_STMT(BPF_MISC + BPF_TAX, 0),

    /* Load the word in skb data at offset X + sizeof(struct nlattr) into A.
     * (skb->data + X + sizeof(nlattr)) points to the group number.
     */
    BPF_STMT(BPF_LD + BPF_W + BPF_IND, sizeof(struct nlattr)),

    /* Perform the actual group comparison.
     * The inmediate value (k) of this instruction must be replaced with the
     * actual group_id.
     */
#define FILTER_GROUP_INS 6
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0xDEADC0DE, 1, 0),	 /* pass */

    /* Return zero, i.e: drop. */
    BPF_STMT(BPF_RET + BPF_K, (u_int) 0),

    /* Return -1, i.e: pass. */
    BPF_STMT(BPF_RET + BPF_K, (u_int) -1),
};

static int psample_set_filter(struct nl_sock *sock, int group_id) {
    struct sock_fprog fprog = {};
    int error;

    fprog.len = ARRAY_SIZE(psample_group_filter);
    fprog.filter = xmalloc(sizeof(psample_group_filter));
    memcpy(fprog.filter, psample_group_filter,
           sizeof(psample_group_filter));

    /* Replace the group number */
    fprog.filter[FILTER_GROUP_INS].k = ntohl(group_id);

    return sock_attach_filter(nl_sock_fd(sock), &fprog);
}

/* Connects socket to the psample multicast group. */
int psample_connect(struct nl_sock *sock, bool all_nsid,
                    const uint32_t *group_id) {
    unsigned int mcast_group;
    int error;

    error = psample_mcgroup(&mcast_group);
    if (error) {
        return error;
    }

    if (all_nsid) {
        nl_sock_listen_all_nsid(sock, true);
    }

    if (group_id) {
        psample_set_filter(sock, *group_id);
    }

    error = nl_sock_join_mcgroup(sock, mcast_group);
    if (error) {
        VLOG_ERR("cannot join psample multicast group: %i", error);
        return error;
    }
    return 0;
}
