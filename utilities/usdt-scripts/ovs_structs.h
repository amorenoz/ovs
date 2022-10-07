typedef unsigned int __uint32_t;
typedef __uint32_t uint32_t;

typedef _Atomic unsigned int  atomic_uint;

struct atomic_count {
	atomic_uint                count;                /*     0     4 */

	/* size: 4, cachelines: 1, members: 1 */
	/* last cacheline: 4 bytes */
};
typedef struct atomic_count atomic_count;

struct seq;

struct ovs_refcount {
	atomic_uint                count;                /*     0     4 */

	/* size: 4, cachelines: 1, members: 1 */
	/* last cacheline: 4 bytes */
};

struct ovs_barrier_impl {
	uint32_t                   size;                 /*     0     4 */
	atomic_count               count;                /*     4     4 */
	struct seq *               seq;                  /*     8     8 */
	struct ovs_refcount        refcnt;               /*    16     4 */

	/* size: 24, cachelines: 1, members: 4 */
	/* padding: 4 */
	/* last cacheline: 24 bytes */
};


struct ovs_list;

struct ovs_list {
	struct ovs_list *          prev;                 /*     0     8 */
	struct ovs_list *          next;                 /*     8     8 */

	/* size: 16, cachelines: 1, members: 2 */
	/* last cacheline: 16 bytes */
};

struct dpif;

struct dpif_backer;

struct handler;

typedef unsigned int __uint32_t;
typedef __uint32_t uint32_t;

struct revalidator;

struct latch {
	int                        fds[2];               /*     0     8 */

	/* size: 8, cachelines: 1, members: 1 */
	/* last cacheline: 8 bytes */
};

struct seq;

struct ovs_barrier_impl;


struct ovs_barrier {
	struct {
		_Atomic struct ovs_barrier_impl *  p;    /*     0     8 */
	} impl;                                          /*     0     8 */

	/* size: 8, cachelines: 1, members: 1 */
	/* last cacheline: 8 bytes */
};

struct dpif_flow_dump;

typedef _Atomic _Bool  atomic_bool;



struct umap;

typedef _Atomic unsigned int  atomic_uint;

typedef _Atomic long long int  atomic_llong;

struct __pthread_internal_list;

struct __pthread_internal_list {
	struct __pthread_internal_list * __prev;         /*     0     8 */
	struct __pthread_internal_list * __next;         /*     8     8 */

	/* size: 16, cachelines: 1, members: 2 */
	/* last cacheline: 16 bytes */
};
typedef struct __pthread_internal_list __pthread_list_t;

struct __pthread_mutex_s {
	int                        __lock;               /*     0     4 */
	unsigned int               __count;              /*     4     4 */
	int                        __owner;              /*     8     4 */
	unsigned int               __nusers;             /*    12     4 */
	int                        __kind;               /*    16     4 */
	short int                  __spins;              /*    20     2 */
	short int                  __elision;            /*    22     2 */
	__pthread_list_t           __list;               /*    24    16 */

	/* size: 40, cachelines: 1, members: 8 */
	/* last cacheline: 40 bytes */
};

typedef union {
	struct __pthread_mutex_s   __data;             /*     0    40 */
	char                       __size[40];         /*     0    40 */
	long int                   __align;            /*     0     8 */
} pthread_mutex_t;

struct ovs_mutex {
	pthread_mutex_t            lock;                 /*     0    40 */
	const char  *              where;                /*    40     8 */

	/* size: 48, cachelines: 1, members: 2 */
	/* last cacheline: 48 bytes */
};

struct unixctl_conn;

typedef long unsigned int __uint64_t;
typedef __uint64_t uint64_t;

typedef long unsigned int size_t;

struct udpif {
	struct ovs_list            list_node;            /*     0    16 */
	struct dpif *              dpif;                 /*    16     8 */
	struct dpif_backer *       backer;               /*    24     8 */
	struct handler *           handlers;             /*    32     8 */
	uint32_t                   n_handlers;           /*    40     4 */

	/* XXX 4 bytes hole, try to pack */

	struct revalidator *       revalidators;         /*    48     8 */
	uint32_t                   n_revalidators;       /*    56     4 */
	struct latch               exit_latch;           /*    60     8 */

	/* XXX 4 bytes hole, try to pack */

	/* --- cacheline 1 boundary (64 bytes) was 8 bytes ago --- */
	struct seq *               reval_seq;            /*    72     8 */
	_Bool                      reval_exit;           /*    80     1 */

	/* XXX 7 bytes hole, try to pack */

	struct ovs_barrier         reval_barrier;        /*    88     8 */
	struct dpif_flow_dump *    dump;                 /*    96     8 */
	long long int              dump_duration;        /*   104     8 */
	struct seq *               dump_seq;             /*   112     8 */
	atomic_bool                enable_ufid;          /*   120     1 */
	_Bool                      pause;                /*   121     1 */

	/* XXX 2 bytes hole, try to pack */

	struct latch               pause_latch;          /*   124     8 */

	/* XXX 4 bytes hole, try to pack */

	/* --- cacheline 2 boundary (128 bytes) was 8 bytes ago --- */
	struct ovs_barrier         pause_barrier;        /*   136     8 */
	struct umap *              ukeys;                /*   144     8 */
	unsigned int               max_n_flows;          /*   152     4 */
	unsigned int               avg_n_flows;          /*   156     4 */
	atomic_uint                flow_limit;           /*   160     4 */
	atomic_uint                n_flows;              /*   164     4 */
	atomic_llong               n_flows_timestamp;    /*   168     8 */
	struct ovs_mutex           n_flows_mutex;        /*   176    48 */
	/* --- cacheline 3 boundary (192 bytes) was 32 bytes ago --- */
	struct unixctl_conn * *    conns;                /*   224     8 */
	uint64_t                   conn_seq;             /*   232     8 */
	size_t                     n_conns;              /*   240     8 */
	long long int              offload_rebalance_time; /*   248     8 */

	/* size: 256, cachelines: 4, members: 29 */
	/* sum members: 235, holes: 5, sum holes: 21 */
};


