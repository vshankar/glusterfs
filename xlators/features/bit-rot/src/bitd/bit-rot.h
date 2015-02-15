 /*
   Copyright (c) 2014 Red Hat, Inc. <http://www.redhat.com>
   This file is part of GlusterFS.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/
#ifndef __BIT_ROT_H__
#define __BIT_ROT_H__

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include "glusterfs.h"
#include "logging.h"
#include "dict.h"
#include "xlator.h"
#include "defaults.h"
#include "syncop.h"
#include "changelog.h"
#include "timer-wheel.h"
#include "bit-rot-common.h"
#include "bit-rot-stub-mem-types.h"
#include <openssl/sha.h>

#define BR_WORKERS 4

#define signature_size(hl) (sizeof (br_isignature_t) + hl + 1)

struct br_child {
        char child_up; /* Indicates whether this child is up or not */
        xlator_t *xl; /* The client xlator corresponding to this child */
        inode_table_t *table; /* Inode table for this child */
        char brick_path[PATH_MAX]; /* Brick export directory of this child */
        struct list_head list; /* hook to attach to the list of UP children */
};

typedef struct br_child br_child_t;

struct br_obj_n_workers {
        struct list_head objects; /* queue of objects expired from the timer
                                     wheel and ready to be picked up for
                                     signing */
        pthread_t workers[BR_WORKERS]; /* Threads which pick up the objects
                                          from the above queue and start
                                          signing each object */
};

typedef struct br_obj_n_workers br_obj_n_workers_t;

struct br_private {
        struct list_head bricks; /* list of bricks from which CHILD_UP has been
                                    received */
        pthread_mutex_t lock;
        pthread_cond_t cond; /* for handling CHILD_UP notifications */
        pthread_cond_t object_cond; /* for handling signing of objects */
        int child_count;
        br_child_t *children; /* list of subvolumes */
        int up_children;
        pthread_t thread; /* thread for connecting each UP child with
                             changelog */
        struct tvec_base *timer_wheel; /* timer wheel where the objects which
                                          changelog has sent sits and waits for
                                          expiry */
        br_obj_n_workers_t *obj_queue; /* place holder for all the objects that
                                          are expired from timer wheel and ready
                                          to be picked up for signing and the
                                          workers which sign the objects */
};

typedef struct br_private br_private_t;

struct br_object {
        xlator_t *this;

        uuid_t gfid;

        unsigned long signedversion;    /* version aginst which this object will
                                           be signed */
        br_child_t *child;              /* object's subvolume */

        struct list_head list;          /* hook to add to the queue once the
                                           object is expired from timer wheel */
        void *data;
};

typedef struct br_object br_object_t;

struct br_local {
        loc_t loc;
        fd_t  *fd; /* is it needed? I am simply adding this. Think everytime
                      this structure is viewed. Remove once its realized that
                      fd is not needed in the local
                   */
        //xlator_t *subvolume;
        br_child_t *child;
};

typedef struct br_local br_local_t;

struct br_inode {
        xlator_t *subvol;
        struct rpc_clnt *rpc;
};

typedef struct br_inode br_inode_t;

struct br_fd {
        xlator_t *subvol;
        struct rpc_clnt *rpc;
};

typedef struct br_fd br_fd_t;

void *
br_brick_init (void *xl, struct gf_brick_spec *brick);

void
br_brick_fini (void *xl, char *brick, void *data);

void
br_brick_callback (void *xl, char *brick,
                   void *data, changelog_event_t *ev);

int32_t
br_sign_object (br_object_t *object);

void *
br_process_object (void *arg);

void
br_add_object_to_queue (struct gf_tw_timer_list *timer, void *data,
                        unsigned long call_time);

void
br_fill_brick_spec (struct gf_brick_spec *brick, char *path);

int32_t
br_brick_connect (xlator_t *this, br_child_t *child);

void *
br_handle_events (void *arg);

int32_t
br_object_read_block_and_sign (xlator_t *this, fd_t *fd, br_object_t *object,
                               off_t offset, size_t size, unsigned char *md);

fd_t *
br_object_open (xlator_t *this, br_object_t *object, inode_t *inode);

inode_t *
br_object_lookup (xlator_t *this, br_object_t *object, struct iatt *iatt);

#endif /* __BIT_ROT_H__ */
