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

#ifndef OPENVSWITCH_SAMPLES_H
#define OPENVSWITCH_SAMPLES_H 1

#include "openvswitch/types.h"
#include "openvswitch/ofp-actions.h"

#ifdef __cplusplus
extern "C" {
#endif

struct flow_sample {
    uint16_t probability;   /* Sampling probability. */
    uint32_t collector_set_id; /* ID of IPFIX collector set. */
    uint32_t obs_domain_id; /* Observation Domain ID. */
    uint32_t obs_point_id;  /* Observation Point ID. */
    odp_port_t output_odp_port; /* The output odp port. */
    enum nx_action_sample_direction direction;
};

/* Decode a flow_sample user action cookie. Returns zero if success. */
int sample_decode_action_cookie(const void *user_data, uint16_t len,
                                struct flow_sample *sample);

#endif /* samples.h */
