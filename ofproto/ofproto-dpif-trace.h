#ifndef OFPROTO_TRACE_H
#define OFPROTO_TRACE_H 1

#include "odp-netlink.h"
#include "openvswitch/ofp-port.h"
#include "openvswitch/match.h"

struct flow;
struct ofproto_dpif;
struct xlate_in;
struct xlate_out;

/* Tracing configuration. */
enum dpif_tracing_type {
    DPIF_TRACE_LOG,
};

struct dpif_tracing_config {
    enum dpif_tracing_type type;
    struct ofputil_port_map port_map;
    const char *filter_expr;
};

struct dpif_tracing {
    /* Configuration */
    enum dpif_tracing_type type;

    /* Match */
    struct match filter;
};

/* dpif_tracing object. */
struct dpif_tracing * dpif_tracing_create(const struct dpif_tracing_config *);
void dpif_tracing_destroy(const struct dpif_tracing *);
void dpif_tracing_format(const struct dpif_tracing *, struct ds* );
/* dpif-tracer object. */
struct dpif_tracer* dpif_tracer_create(const struct dpif_tracing *,
                                       const char* , ...);
struct dpif_tracer * dpif_tracer_from_flow(const struct dpif_tracing *,
                                           const struct flow *,
                                           const ofp_port_t *ofp_in_port);

struct ovs_list * dpif_tracer_xlate_start(struct dpif_tracer *,
                                          struct xlate_in *);
void
dpif_tracer_xlate_end(struct dpif_tracer *, struct xlate_in *,
                       struct xlate_out *, enum xlate_error);


# define dpif_tracer_addf(TRACER, FORMAT, ...)               \
    do {                                                     \
        if (OVS_UNLIKELY(TRACER)) {                          \
            dpif_tracer_addf__(TRACER, FORMAT, __VA_ARGS__); \
        }                                                    \
    } while(0)
void OVS_PRINTF_FORMAT(2, 3) dpif_tracer_addf__(struct dpif_tracer *,
                                                const char *, ...);

# define dpif_tracer_add(TRACER, TEXT, ...)                  \
    do {                                                     \
        if (OVS_UNLIKELY(TRACER)) {                          \
            dpif_tracer_add__(TRACER, TEXT);                 \
        }                                                    \
    } while(0)
void dpif_tracer_add__(struct dpif_tracer *, const char *);
void dpif_tracer_consume(struct dpif_tracer *);
void dpif_tracer_emit(struct dpif_tracer *);

#endif // #ifndef OFPROTO_TRACE_H
