
#include <config.h>

#include "ofproto-dpif-trace.h"

#include "ofproto-dpif.h"
#include "ofproto-dpif-xlate.h"
#include "ofproto-dpif-xlate-trace.h"
#include "openvswitch/ofp-flow.h"
#include "openvswitch/ofp-port.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_trace);

struct dpif_tracer {
    struct ds output;    /* Output string buffer. */

    /* For xlate tracing */
    struct ovs_list xlate_nodes;
    struct flow xlate_initial_flow;
};

struct dpif_tracing *
dpif_tracing_create(const struct dpif_tracing_config *config)
{
    struct dpif_tracing *tracing= xzalloc(sizeof *tracing);
    struct flow flow_filter;
    struct flow_wildcards wc_filter;

    if (!config->filter_expr) {
        match_init_catchall(&tracing->filter);
    } else {
        char *err = parse_ofp_exact_flow(&flow_filter, &wc_filter, NULL,
                                         config->filter_expr,
                                         &config->port_map);

        if (err) {
            VLOG_ERR("Faled to configure dpif tracing (%s)", err);
            free(err);
            free(tracing);
            return NULL;
        }
        match_init(&tracing->filter, &flow_filter, &wc_filter);
    }
    return tracing;
}

void
dpif_tracing_format(const struct dpif_tracing *tracing, struct ds* output)
{
    switch (tracing->type) {
    case DPIF_TRACE_LOG:
        ds_put_format(output, "mode=log filter: ");
        match_format(&tracing->filter, NULL, output, 0);
        break;
    }
}

static bool
dpif_tracing_matches(const struct dpif_tracing *tracing,
                     const struct flow *flowp,
                     const ofp_port_t *ofp_in_port)
{
    bool matches = false;
    struct minimatch minimatch;
    struct flow flow;
    if (ofp_in_port) {
        flow = *flowp;
        flow.in_port.ofp_port = *ofp_in_port;
        flowp = &flow;
    }
    minimatch_init(&minimatch, &tracing->filter);
    if (minimatch_matches_flow(&minimatch, flowp)) {
        matches = true;
    }
    minimatch_destroy(&minimatch);
    return matches;
}

/* dpif_tracer */
static
void dpif_tracer_init(struct dpif_tracer *tracer)
{
    ovs_list_init(&tracer->xlate_nodes);
    ds_init(&tracer->output);
}

/* Destroys the tracer without consuming its result. */
static void
dpif_tracer_destroy(struct dpif_tracer *tracer)
{
    xtrace_node_list_destroy(&tracer->xlate_nodes);
    ds_destroy(&tracer->output);
}

static
void dpif_tracer_output(struct dpif_tracer *tracer)
{
    if (tracer->output.length > 0) {
        ds_chomp(&tracer->output, '\n');
        VLOG_INFO("%s", ds_cstr(&tracer->output));
    }
}

/* Consumes and destroys the tracer emiting the trace result. */
void
dpif_tracer_consume(struct dpif_tracer *tracer)
{
    if (OVS_UNLIKELY(tracer)) {
        dpif_tracer_output(tracer);
        dpif_tracer_destroy(tracer);
    }
}

/* Emit traces and reinitializes the tracer for future use. */
void
dpif_tracer_emit(struct dpif_tracer *tracer)
{
    if (OVS_UNLIKELY(tracer)) {
        dpif_tracer_output(tracer);
        xtrace_node_list_destroy(&tracer->xlate_nodes);
        ds_destroy(&tracer->output);
        dpif_tracer_init(tracer);
    }
}

struct dpif_tracer *
dpif_tracer_from_flow(const struct dpif_tracing *tracing,
                      const struct flow *flow,
                      const ofp_port_t *ofp_in_port)
{
    struct dpif_tracer *tracer;
    if (!dpif_tracing_matches(tracing, flow, ofp_in_port)) {
        return NULL;
    }

    /* Log initial flow */
    struct ds flowstr;
    ds_init(&flowstr);
    flow_format(&flowstr, flow, NULL);

    tracer = dpif_tracer_create(tracing,
                                "Tracer created from flow: %s",
                                ds_cstr(&flowstr));
    ds_destroy(&flowstr);
    return tracer;
}

struct dpif_tracer * OVS_PRINTF_FORMAT(2, 3)
dpif_tracer_create(const struct dpif_tracing *tracing OVS_UNUSED,
                   const char* format, ...)
{
    struct dpif_tracer *tracer = xzalloc(sizeof *tracer);
    dpif_tracer_init(tracer);

    va_list args;
    va_start(args, format);
    dpif_tracer_add__(tracer, xvasprintf(format, args));
    va_end(args);

    return tracer;
}

/* Tracing helpers */
struct ovs_list *
dpif_tracer_xlate_start(struct dpif_tracer *tracer,
                        struct xlate_in *xin) {

    if (OVS_UNLIKELY(tracer)) {
        struct ofputil_port_map map = OFPUTIL_PORT_MAP_INITIALIZER(&map);
        ofproto_append_ports_to_map(&map, xin->ofproto->up.ports);
        /* Copy initial flow out of xin.flow.  It differs from '*flow' because
         * xlate_in_init() initializes actset_output to OFPP_UNSET. */
        tracer->xlate_initial_flow = xin->flow;
        ofproto_xtrace_start(xin, &map, &tracer->output);
        if (!ovs_list_is_empty(&tracer->xlate_nodes)) {
            VLOG_ERR("Started new xlate tracing without consuming previous");
            xtrace_node_list_destroy(&tracer->xlate_nodes);
        }
        return &tracer->xlate_nodes;
    }
    return NULL;
}

void
dpif_tracer_xlate_end(struct dpif_tracer *tracer,
                      struct xlate_in *xin,
                      struct xlate_out *xout,
                      enum xlate_error xerr)
{
    if (OVS_UNLIKELY(tracer)) {
        struct ofputil_port_map map = OFPUTIL_PORT_MAP_INITIALIZER(&map);
        ofproto_append_ports_to_map(&map, xin->ofproto->up.ports);

        struct ds output = DS_EMPTY_INITIALIZER;
        ofproto_xtrace_end(&tracer->xlate_initial_flow, &tracer->xlate_nodes,
                           xin, xout, xerr, &map, &output);
        dpif_tracer_add__(tracer, ds_cstr(&output));
        ds_destroy(&output);
    }
}

void OVS_PRINTF_FORMAT(2, 3)
dpif_tracer_addf__(struct dpif_tracer *tracer, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    char *text = xvasprintf(format, args);
    ds_put_cstr(&tracer->output, text);
    ds_put_cstr(&tracer->output, "\n");
    va_end(args);
    free(text);
}

void
dpif_tracer_add__(struct dpif_tracer *tracer, const char *text)
{
    ds_put_cstr(&tracer->output, text);
    ds_put_cstr(&tracer->output, "\n");
}
