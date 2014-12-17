/*
   Copyright (c) 2013 Red Hat, Inc. <http://www.redhat.com>
   This file is part of GlusterFS.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/

#include <errno.h>
#include <dirent.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/resource.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <string.h>

#include "globals.h"
#include "glusterfs.h"
#include "logging.h"
#include "defaults.h"
#include "syncop.h"

#include "gf-changelog-rpc.h"
#include "gf-changelog-helpers.h"

/* from the changelog translator */
#include "changelog-misc.h"
#include "changelog-mem-types.h"

#define GF_CHANGELOG_EVENT_POOL_SIZE   16384
static int
gf_changelog_ctx_defaults_init (glusterfs_ctx_t *ctx)
{
        cmd_args_t    *cmd_args = NULL;
        struct rlimit  lim = {0, };
        call_pool_t   *pool = NULL;
        int            ret         = -1;

        ret = xlator_mem_acct_init (THIS, gf_changelog_mt_end);
        if (ret != 0) {
                return ret;
        }

        ctx->process_uuid = generate_glusterfs_ctx_id ();
        if (!ctx->process_uuid)
                return -1;

        ctx->page_size  = 128 * GF_UNIT_KB;

        ctx->iobuf_pool = iobuf_pool_new ();
        if (!ctx->iobuf_pool)
                return -1;

        ctx->event_pool = event_pool_new (GF_CHANGELOG_EVENT_POOL_SIZE);
        if (!ctx->event_pool)
                return -1;

        pool = GF_CALLOC (1, sizeof (call_pool_t),
                          gf_changelog_mt_libgfchangelog_call_pool_t);
        if (!pool)
                return -1;

        /* frame_mem_pool size 112 * 64 */
        pool->frame_mem_pool = mem_pool_new (call_frame_t, 32);
        if (!pool->frame_mem_pool)
                return -1;

        /* stack_mem_pool size 256 * 128 */
        pool->stack_mem_pool = mem_pool_new (call_stack_t, 16);

        if (!pool->stack_mem_pool)
                return -1;

        ctx->stub_mem_pool = mem_pool_new (call_stub_t, 16);
        if (!ctx->stub_mem_pool)
                return -1;

        ctx->dict_pool = mem_pool_new (dict_t, 32);
        if (!ctx->dict_pool)
                return -1;

        ctx->dict_pair_pool = mem_pool_new (data_pair_t, 512);
        if (!ctx->dict_pair_pool)
                return -1;

        ctx->dict_data_pool = mem_pool_new (data_t, 512);
        if (!ctx->dict_data_pool)
                return -1;

        INIT_LIST_HEAD (&pool->all_frames);
        LOCK_INIT (&pool->lock);
        ctx->pool = pool;

        pthread_mutex_init (&(ctx->lock), NULL);

        cmd_args = &ctx->cmd_args;

        INIT_LIST_HEAD (&cmd_args->xlator_options);

        lim.rlim_cur = RLIM_INFINITY;
        lim.rlim_max = RLIM_INFINITY;
        setrlimit (RLIMIT_CORE, &lim);

        return 0;
}

void
__attribute__ ((constructor)) gf_changelog_ctor (void)
{
        int              ret  = 0;
        gf_private_t    *priv = NULL;
        glusterfs_ctx_t *ctx  = NULL;

        ctx = glusterfs_ctx_new ();
        if (!ctx)
                goto default_return;

        if (glusterfs_globals_init (ctx))
                goto free_ctx;

        THIS->ctx = ctx;
        if (gf_changelog_ctx_defaults_init (ctx))
                goto free_ctx;

        ctx->env = syncenv_new (0, 0, 0);
        if (!ctx->env)
                goto free_ctx;

        if (xlator_mem_acct_init (THIS, gf_changelog_mt_end))
                goto free_ctx;

        priv = GF_CALLOC (1, sizeof (gf_private_t),
                          gf_changelog_mt_libgfchangelog_t);
        if (!priv)
                goto free_ctx;
        THIS->private = priv;
        INIT_LIST_HEAD (&priv->connections);

        /* poller thread */
        ret = pthread_create (&priv->poller, NULL, changelog_rpc_poller, THIS);
        if (ret != 0) {
                gf_log (THIS->name, GF_LOG_ERROR,
                        "failed to spawn poller thread");
                goto free_ctx;
        }

        goto default_return;

 free_ctx:
        free (ctx);
        THIS->ctx = NULL;
        THIS->private = NULL;
 default_return:
        return;
}

void gf_cleanup_entries (xlator_t *this, gf_private_t *priv);

void
__attribute__ ((destructor)) gf_changelog_dtor (void)
{
        int              ret   = 0;
        xlator_t        *this  = NULL;
        glusterfs_ctx_t *ctx   = NULL;
        gf_private_t    *priv  = NULL;

        this = THIS;
        if (!this || !this->private)
                return;
        priv = this->private;

        (void)gf_thread_cleanup (this, priv->poller);
        gf_cleanup_entries (this, priv);

        ctx = this->ctx;
        if (ctx) {
                pthread_mutex_destroy (&ctx->lock);
                free (ctx);
                ctx = NULL;
        }
}

/* TODO: cleanup clnt/svc on failure */
int
gf_changelog_setup_rpc (xlator_t *this,
                        gf_changelog_t *entry, int proc)
{
        int              ret = 0;
        rpcsvc_t        *svc = NULL;
        struct rpc_clnt *rpc = NULL;

        /**
         * Initialize a connect back socket. A probe() RPC call to the server
         * triggers a reverse connect.
         */
        svc = gf_changelog_reborp_init_rpc_listner (this, entry->brick,
                                                    RPC_SOCK (entry), entry);
        if (!svc)
                goto error_return;
        RPC_REBORP (entry) = svc;

        /* Initialize an RPC client */
        rpc = gf_changelog_rpc_init (this, entry);
        if (!rpc)
                goto error_return;
        RPC_PROBER (entry) = rpc;

        /**
         * Probe changelog translator for reverse connection. After a successful
         * call, there's less use of the client and can be disconnected, but
         * let's leave the connection active for any future RPC calls.
         */
        ret = gf_changelog_invoke_rpc (this, entry, proc);
        if (ret) {
                gf_log (this->name, GF_LOG_ERROR, "Probe RPC failed");
                goto error_return;
        }

        return 0;

 error_return:
        return -1;
}

void
gf_cleanup_entries (xlator_t *this, gf_private_t *priv)
{
        gf_changelog_t  *entry = NULL;
        gf_changelog_t  *tmp   = NULL;

        /* invoke ->fini for each entry */
        list_for_each_entry_safe (entry, tmp, &priv->connections, list) {
                list_del (&entry->list);
                entry->fini (this, entry->brick, entry->ptr);
        }
}

int
gf_init_event (gf_changelog_t *entry)
{
        int ret = 0;
        struct gf_event_list *ev = NULL;

        ev = &entry->event;

        ev->entry = entry;

        ret = pthread_mutex_init (&ev->lock, NULL);
        if (ret != 0)
                goto error_return;
        ret = pthread_cond_init (&ev->cond, NULL);
        if (ret != 0)
                goto cleanup_mutex;
        INIT_LIST_HEAD (&ev->events);

        ev->next_seq = 0;  /* bootstrap sequencing */

        if (entry->ordered) {
                ret = pthread_create (&ev->invoker, NULL,
                                      gf_changelog_callback_invoker, ev);
                if (ret != 0)
                        goto cleanup_cond;
        }

        return 0;

 cleanup_cond:
        (void) pthread_cond_destroy (&ev->cond);
 cleanup_mutex:
        (void) pthread_mutex_destroy (&ev->lock);
 error_return:
        return -1;
}

void
gf_cleanup_event (gf_changelog_t *entry)
{
        xlator_t             *this = NULL;
        struct gf_event_list *ev   = NULL;

        this = entry->this;
        ev = &entry->event;

        (void) gf_thread_cleanup (this, ev->invoker);

        (void) pthread_mutex_destroy (&ev->lock);
        (void) pthread_cond_destroy (&ev->cond);

        ev->entry = NULL;
}

int
gf_init_entry (xlator_t *this, gf_private_t *priv,
               struct gf_brick_spec *brick, gf_boolean_t ordered)
{
        int ret = 0;
        gf_changelog_t *entry = NULL;

        if (!brick->callback || !brick->init || !brick->fini)
                goto error_return;

        entry = GF_CALLOC (1, sizeof (*entry),
                           gf_changelog_mt_libgfchangelog_t);
        if (!entry)
                goto error_return;
        (void) strncpy (entry->brick, brick->brick_path, PATH_MAX);

        entry->this = this;

        entry->ordered = ordered;
        if (ordered) {
                ret = gf_init_event (entry);
                if (ret)
                        goto error_return;
        }

        entry->fini         = brick->fini;
        entry->callback     = brick->callback;
        entry->connected    = brick->connected;
        entry->disconnected = brick->disconnected;

        entry->ptr = brick->init (this, brick);
        if (!entry->ptr)
                goto cleanup_entry;
        /**
         * store owners private data for API access. This is only valid
         * for one process per brick interested in journal APIs
         */
        priv->api = entry->ptr;

        INIT_LIST_HEAD (&entry->list);
        list_add_tail (&entry->list, &priv->connections);

        ret = gf_changelog_setup_rpc (this, entry, CHANGELOG_RPC_PROBE_SIMPLE);
        if (ret)
                goto cleanup_entry;
        return 0;

 cleanup_entry:
        list_del (&entry->list);
        if (ordered)
                gf_cleanup_event (entry);
        GF_FREE (entry);
 error_return:
        return -1;
}

/* TODO: cleanup clnt, svc */
void
gf_cleanup_entry (gf_changelog_t *entry)
{
        list_del (&entry->list);
        if (entry->ordered)
                gf_cleanup_event (entry);
        GF_FREE (entry);
}

int
gf_changelog_register_brick (struct gf_brick_spec *brick,
                             char *logfile, int loglevel, gf_boolean_t ordered)
{
        int             ret      = -1;
        int             errn     = 0;
        xlator_t       *this     = NULL;
        gf_changelog_t *entry    = NULL;
        gf_private_t   *priv     = NULL;
        pthread_t       poll_thr = 0;

        this = THIS;
        if (!this->ctx || !this->private)
                goto error_return;
        priv = this->private;

        /* passing ident as NULL means to use default ident for syslog */
        if (gf_log_init (this->ctx, logfile, NULL))
                goto error_return;
        gf_log_set_loglevel ((loglevel == -1) ? GF_LOG_INFO :
                             loglevel);

        ret = gf_init_entry (this, priv, brick, ordered);
        if (ret != 0)
                goto error_return;
        return 0;

 error_return:
        return -1;
}

/**
 * @API
 *  gf_changelog_register()
 *
 * This is _NOT_ a generic register API. It's a special API to handle
 * updates at a journal granulality. This is used by consumers wanting
 * to process persistent journal such as geo-replication via a set of
 * APIs. All of this is required to maintain backward compatibility.
 * Owner specific private data is stored in ->api (in gf_private_t),
 * which is used by APIs to access it's private data. This limits
 * the library access to a single brick, but that's how it used to
 * be anyway.
 *
 * Newer applications wanting to use this library need not face this
 * limitation and reply of the much more feature rich generic register
 * API, which is purely callback based.
 *
 * NOTE: @max_reconnects is not used but required for backward compat.
 *
 * For generic API, refer gf_changelog_register_generic().
 */
int
gf_changelog_register (char *brick_path, char *scratch_dir,
                       char *log_file, int log_level, int max_reconnects)
{
        struct gf_brick_spec brick = {0,};

        brick.brick_path = brick_path;

        brick.init = gf_changelog_journal_init;
        brick.fini = gf_changelog_journal_fini;
        brick.callback = gf_changelog_handle_journal;
        brick.connected = gf_changelog_journal_connect;
        brick.disconnected = gf_changelog_journal_disconnect;

        brick.ptr = scratch_dir;

        return gf_changelog_register_brick (&brick,
                                            log_file, log_level, _gf_true);
}
