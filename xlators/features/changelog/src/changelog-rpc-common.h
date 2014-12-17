/*
   Copyright (c) 2015 Red Hat, Inc. <http://www.redhat.com>
   This file is part of GlusterFS.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/

#ifndef __CHANGELOG_RPC_COMMON_H
#define __CHANGELOG_RPC_COMMON_H

#include "rpcsvc.h"
#include "rpc-clnt.h"
#include "event.h"
#include "call-stub.h"

#include "changelog-xdr.h"
#include "xdr-generic.h"

enum changelog_rpc_procnum {
        CHANGELOG_RPC_PROC_NULL    = 0,
        CHANGELOG_RPC_PROBE_SIMPLE = 1,
        CHANGELOG_RPC_PROBE_FILTER = 2,
        CHANGELOG_RPC_PROC_MAX     = 3,
};

#define CHANGELOG_RPC_PROGNUM   1885957735
#define CHANGELOG_RPC_PROGVER   1

/**
 * reverse connection: data xfer path
 */
enum changelog_reverse_rpc_procnum {
        CHANGELOG_REV_PROC_NULL  = 0,
        CHANGELOG_REV_PROC_EVENT = 1,
        CHANGELOG_REV_PROC_MAX   = 2,
};

#define CHANGELOG_REV_RPC_PROCNUM   1886350951
#define CHANGELOG_REV_RPC_PROCVER   1

typedef struct changelog_rpc {
        rpcsvc_t        *svc;
        struct rpc_clnt *rpc;
        char             sock[UNIX_PATH_MAX];  /* tied to server */
} changelog_rpc_t;

/**
 * Filter flags
 * A client can choose to be notified for selected operations. Selection
 * is performed during probe RPC.
 */

#define CHANGELOG_OP_TYPE_OPEN    1<<0
#define CHANGELOG_OP_TYPE_RELEASE 1<<1
#define CHANGELOG_OP_TYPE_JOURNAL 1<<2

struct ev_open {
        uuid_t gfid;
        uint32_t flags;
};

struct ev_release {
        uuid_t gfid;
};

struct ev_changelog {
        char path[PATH_MAX];
};

typedef struct changelog_event {
        int ev_type;
        union {
                struct ev_open open;
                struct ev_release release;
                struct ev_changelog journal;
        } u;
} changelog_event_t;

#define CHANGELOG_EV_SIZE  sizeof (changelog_event_t)

/* event poller */
void *changelog_rpc_poller (void *);

/* CLIENT API */
struct rpc_clnt *
changelog_rpc_client_init (xlator_t *, void *, char *, rpc_clnt_notify_t);

int
changelog_rpc_sumbit_req (struct rpc_clnt *, void *, call_frame_t *,
                          rpc_clnt_prog_t *, int , struct iovec *, int,
                          struct iobref *, xlator_t *, fop_cbk_fn_t, xdrproc_t);

int
changelog_invoke_rpc (xlator_t *, struct rpc_clnt *,
                      rpc_clnt_prog_t *, int , void *);

/* SERVER API */
int
changelog_rpc_sumbit_reply (rpcsvc_request_t *, void *,
                            struct iovec *, int,struct iobref *, xdrproc_t);
rpcsvc_t *
changelog_rpc_server_init (xlator_t *, char *, void*,
                           rpcsvc_notify_t, struct rpcsvc_program **);
void
changelog_rpc_server_destroy (xlator_t *, rpcsvc_t *, char *,
                              rpcsvc_notify_t, struct rpcsvc_program **);

#endif
