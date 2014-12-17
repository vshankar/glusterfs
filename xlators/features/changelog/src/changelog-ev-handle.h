/*
   Copyright (c) 2015 Red Hat, Inc. <http://www.redhat.com>
   This file is part of GlusterFS.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/

#ifndef __CHANGELOG_EV_HANDLE_H
#define __CHANGELOG_EV_HANDLE_H

#include "list.h"
#include "xlator.h"
#include "rpc-clnt.h"

#include "rot-buffs.h"

struct changelog_clnt;

typedef struct changelog_rpc_clnt {
        xlator_t *this;

        struct changelog_clnt *c_clnt;                  /* back pointer
                                                           to list holder */
        void (*cleanup)(struct changelog_rpc_clnt *);   /* cleanup handler */

        int filter;
        char sock[UNIX_PATH_MAX];

        struct rpc_clnt *rpc;

        struct list_head list;
} changelog_rpc_clnt_t;

/**
 * This structure holds pending and active clients. On probe RPC all
 * an instance of the above structure (@changelog_rpc_clnt) is placed
 * in ->pending and gets moved to ->active on a successful connect.
 *
 * locking rules:
 *
 * Manipulating ->pending
 * ->pending_lock
 *    ->pending
 *
 * Manipulating ->active
 * ->active_lock
 *    ->active
 *
 * Moving object from ->pending to ->active
 * ->pending_lock
 *   ->active_lock
 *
 * Objects are _never_ moved from ->active to ->pending, i.e., during
 * disconnection, the object is destroyed. Well, we could have tried
 * to reconnect, but that's pure waste.. let the other end reconnect.
 */

typedef struct changelog_clnt {
        xlator_t *this;

        /* pending connections */
        pthread_mutex_t pending_lock;
        pthread_cond_t pending_cond;
        struct list_head pending;

        /* current active connections */
        gf_lock_t active_lock;
        struct list_head active;

        gf_lock_t wait_lock;
        struct list_head waitq;

        /* consumer part of rot-buffs */
        rbuf_t *rbuf;
        unsigned long sequence;
} changelog_clnt_t;

void *changelog_ev_connector (void *);

void *changelog_ev_dispatch (void *);

/* APIs */
void
changelog_ev_queue_connection (changelog_clnt_t *, changelog_rpc_clnt_t *);

void
changelog_ev_cleanup_connections (xlator_t *, changelog_clnt_t *);

#endif

