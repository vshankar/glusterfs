/*
   Copyright (c) 2014 Red Hat, Inc. <http://www.redhat.com>
   This file is part of GlusterFS.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/

#include <ctype.h>
#include <sys/uio.h>

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include "glusterfs.h"
#include "xlator.h"
#include "logging.h"

#include "bit-rot.h"
#include <pthread.h>

static int
br_find_child_index (xlator_t *this, xlator_t *child)
{
        br_private_t *priv   = NULL;
        int           i      = -1;
        int           index  = -1;

        GF_VALIDATE_OR_GOTO ("bit-rot", this, out);
        GF_VALIDATE_OR_GOTO (this->name, this->private, out);
        GF_VALIDATE_OR_GOTO (this->name, child, out);

        priv = this->private;

        for (i = 0; i < priv->child_count; i++) {
                if (child == priv->children[i].xl) {
                        index = i;
                        break;
                }
        }

out:
        return index;
}

br_child_t *
br_get_child_from_brick_path (xlator_t *this, char *brick_path)
{
        br_private_t *priv  = NULL;
        br_child_t   *child = NULL;
        br_child_t   *tmp   = NULL;
        int           i     = 0;

        GF_VALIDATE_OR_GOTO ("bit-rot", this, out);
        GF_VALIDATE_OR_GOTO (this->name, this->private, out);
        GF_VALIDATE_OR_GOTO (this->name, brick_path, out);

        priv = this->private;

        pthread_mutex_lock (&priv->lock);
        {
                for (i = 0; i < priv->child_count; i++) {
                        tmp = &priv->children[i];
                        if (!strcmp (tmp->brick_path, brick_path)) {
                                child = tmp;
                                break;
                        }
                }
        }
        pthread_mutex_unlock (&priv->lock);

out:
        return child;
}

/**
 * probably we'll encapsulate brick inside our own structure when
 * needed -- later.
 */
void *
br_brick_init (void *xl, struct gf_brick_spec *brick)
{
        return brick;
}

/**
 * and cleanup things here when allocated br_brick_init().
 */
void
br_brick_fini (void *xl, char *brick, void *data)
{
        return;
}

static inline br_isignature_t *
br_prepare_signature (const unsigned char *sign,
                      unsigned long hashlen,
                      int8_t hashtype, br_object_t *object)
{
        br_isignature_t *signature = NULL;

        /* TODO: use mem-pool */
        signature = GF_CALLOC (1, signature_size (hashlen),
                               gf_br_stub_mt_signature_t);
        if (!signature)
                return NULL;

        /* FIXME: sign against the notified version */
        signature->signedversion = object->signedversion;
        signature->signaturetype = hashtype;
        memcpy (signature->signature, (char *)sign, hashlen);
        signature->signature[hashlen+1] = '\0';

        return signature;
}

/**
 * Do a lookup on the gfid present within the object.
 */
inode_t *
br_object_lookup (xlator_t *this, br_object_t *object, struct iatt *iatt)
{
	inode_t     *inode        = NULL;
	int          ret          = 0;
	loc_t        loc          = {0, };
        inode_t     *linked_inode = NULL;

        GF_VALIDATE_OR_GOTO ("bit-rot", this, out);
        GF_VALIDATE_OR_GOTO (this->name, object, out);

	inode = inode_find (object->child->table, object->gfid);

        if (inode)
                loc.inode = inode;
        else
                loc.inode = inode_new (object->child->table);

	if (!loc.inode)
		goto out;

	uuid_copy (loc.gfid, object->gfid);

	ret = syncop_lookup (object->child->xl, &loc, NULL, iatt, NULL, NULL);
	if (ret < 0)
		goto out;

        /*
         * The file might have been deleted by the application
         * after getting the event, but before doing a lookup.
         * So use linked_inode after inode_link is done.
         */
	linked_inode = inode_link (loc.inode, NULL, NULL, iatt);
	if (linked_inode)
		inode_lookup (linked_inode);

out:
	loc_wipe (&loc);
	return linked_inode;
}

/**
 * open the object with O_RDONLY flags and return the fd. How to let brick
 * know that open is being done by bitd because syncop framework does not allow
 * passing xdata -- may be use frame->root->pid itself.
 */
fd_t *
br_object_open (xlator_t *this, br_object_t *object, inode_t *inode)
{
        int32_t      ret   = -1;
        fd_t        *fd    = NULL;
        loc_t        loc   = {0, };

        GF_VALIDATE_OR_GOTO ("bit-rot", this, out);
        GF_VALIDATE_OR_GOTO (this->name, object, out);
        GF_VALIDATE_OR_GOTO (this->name, inode, out);

        fd = fd_create (inode, 0);
        if (!fd) {
                gf_log (this->name, GF_LOG_ERROR, "failed to create fd for the "
                        "inode %s", uuid_utoa (inode->gfid));
                goto out;
        }

        loc.inode = inode_ref (inode);
	uuid_copy (loc.gfid, inode->gfid);

        ret = syncop_open (object->child->xl, &loc, O_RDONLY, fd);
	if (ret) {
		fd_unref (fd);
		fd = NULL;
	} else {
		fd_bind (fd);
	}

        loc_wipe (&loc);

out:
        return fd;
}

/**
 * read 128k block from the object @object from the offset @offset
 * and return the buffer.
 */
int32_t
br_object_read_block_and_sign (xlator_t *this, fd_t *fd, br_object_t *object,
                               off_t offset, size_t size, unsigned char *md)
{
        int32_t        ret    = -1;
        struct iovec  *iovec  = NULL;
        struct iobref *iobref = NULL;
        int            count  = 0;

        GF_VALIDATE_OR_GOTO ("bit-rot", this, out);
        GF_VALIDATE_OR_GOTO (this->name, fd, out);
        GF_VALIDATE_OR_GOTO (this->name, fd->inode, out);

        ret = syncop_readv (object->child->xl, fd, size, offset, 0,
                            &iovec, &count, &iobref);
        if (ret <= 0) {
                gf_log (this->name, GF_LOG_ERROR, "readv on %s failed (%s)",
                        uuid_utoa (fd->inode->gfid), strerror (errno));
                ret = -1;
                goto out;
        }

        md = SHA256 ((const unsigned char *)(iovec->iov_base), iovec->iov_len,
                     md);

        ret = 0;

out:
        return ret;
}

/**
 * Sign a given object. This routine runs full throttle. There needs to be
 * some form of priority scheduling and/or read burstness to avoid starving
 * (or kicking) client I/O's.
 */
int32_t
br_sign_object (br_object_t *object)
{
        int32_t         ret           = -1;
        inode_t        *linked_inode  = NULL;
        xlator_t       *this          = NULL;
        fd_t           *fd            = NULL;
        dict_t         *xattr         = NULL;
        unsigned char  *md            = NULL;
        off_t           offset        = 0;
        struct iatt     iatt          = {0, };
        size_t          block         = 128 * 1024;
        br_isignature_t *sign         = NULL;
        pid_t           pid           = GF_CLIENT_PID_BITD;

        GF_VALIDATE_OR_GOTO ("bit-rot", object, out);

        this = object->this;

        /**
         * FIXME: This is required as signing an object is restricted to
         * clients with special frame->root->pid. Change the way client
         * pid is set.
         */
        syncopctx_setfspid (&pid);

        linked_inode = br_object_lookup (this, object, &iatt);
        if (!linked_inode) {
                gf_log (this->name, GF_LOG_ERROR, "lookup on the gfid %s "
                        "failed", uuid_utoa (object->gfid));
                goto out;
        }

        fd = br_object_open (this, object, linked_inode);
        if (!fd) {
                gf_log (this->name, GF_LOG_ERROR, "opening the object %s "
                        "failed", uuid_utoa (linked_inode->gfid));
                goto out;
        }

        md = GF_CALLOC (SHA256_DIGEST_LENGTH, sizeof (*md),
                        gf_common_mt_char);
        if (!md) {
                gf_log (this->name, GF_LOG_ERROR, "failed to allocate memory "
                        "for saving hash of the with offset %lu for object %s",
                        offset, uuid_utoa (fd->inode->gfid));
                goto out;
        }

        for (offset = 0; offset < iatt.ia_size; offset += block) {
                ret = br_object_read_block_and_sign (this, fd, object, offset,
                                                     block, md);
                if (ret) {
                        gf_log (this->name, GF_LOG_ERROR, "reading block with "
                                "offset %lu of object %s failed", offset,
                                uuid_utoa (fd->inode->gfid));
                        goto out;
                }
        }

        gf_log (this->name, GF_LOG_DEBUG, "Signature: %s", md);

        sign = br_prepare_signature
                (md, SHA256_DIGEST_LENGTH, BR_SIGNATURE_TYPE_SHA256, object);
        if (!sign) {
                gf_log (this->name, GF_LOG_ERROR, "failed to get the signature "
                        "for the object %s", uuid_utoa (fd->inode->gfid));
                goto out;
        }

        xattr = dict_for_key_value
                (GLUSTERFS_SET_OBJECT_SIGNATURE,
                 (void *)sign, signature_size (SHA256_DIGEST_LENGTH));

        if (!xattr) {
                gf_log (this->name, GF_LOG_ERROR, "failed to get the dict. sign"
                        " failed for the object %s",
                        uuid_utoa (fd->inode->gfid));
                goto out;
        }

        ret = syncop_fsetxattr (object->child->xl, fd, xattr, 0);
        if (ret) {
                gf_log (this->name, GF_LOG_ERROR, "fsetxattr of signature to "
                        "the object %s failed", uuid_utoa (fd->inode->gfid));
                goto out;
        }

        ret = 0;

out:
        if (linked_inode)
                inode_unref (linked_inode);

        if (fd)
                fd_unref (fd);

        if (sign)
                GF_FREE (sign);

        if (xattr)
                dict_unref (xattr);

        return ret;
}

static inline br_object_t *__br_pick_object (br_private_t *priv)
{
        br_object_t *object = NULL;

        while (list_empty (&priv->obj_queue->objects)) {
                pthread_cond_wait (&priv->object_cond, &priv->lock);
        }

        object = list_first_entry
                (&priv->obj_queue->objects, br_object_t, list);
        list_del_init (&object->list);

        return object;
}

/**
 * This is the place where the signing of the objects is triggered.
 */
void *
br_process_object (void *arg)
{
        xlator_t     *this   = NULL;
        br_object_t  *object = NULL;
        br_private_t *priv   = NULL;
        int32_t       ret    = -1;

        this = arg;
        priv = this->private;

        for (;;) {
                pthread_mutex_lock (&priv->lock);
                {
                        object = __br_pick_object (priv);
                }
                pthread_mutex_unlock (&priv->lock);

                ret = br_sign_object (object);
                if (ret)
                        gf_log (this->name, GF_LOG_ERROR,
                                "SIGNING FAILURE [%s]", uuid_utoa (object->gfid));
                GF_FREE (object);
        }

        return NULL;
}

/**
 * This function gets kicked in once the object is expired from the
 * timer wheel. This actually adds the object received via notification
 * from the changelog to the queue from where the objects gets picked
 * up for signing.
 *
 * This routine can be made lightweight by introducing an alternate
 * timer-wheel API that dispatches _all_ expired objects in one-shot
 * rather than an object at-a-time. This routine can then just simply
 * be a call to list_splice_tail().
 *
 * NOTE: use call_time to instrument signing time in br_sign_object().
 */
void
br_add_object_to_queue (struct gf_tw_timer_list *timer,
                        void *data, unsigned long call_time)
{
        br_object_t   *object = NULL;
        xlator_t      *this   = NULL;
        br_private_t  *priv   = NULL;

        object = data;
        this   = object->this;
        priv   = this->private;

        pthread_mutex_lock (&priv->lock);
        {
                list_add_tail (&object->list, &priv->obj_queue->objects);
                pthread_cond_broadcast (&priv->object_cond);
        }
        pthread_mutex_unlock (&priv->lock);

        GF_FREE (timer);
        return;
}

/**
 * This callback function registered with the changelog is executed
 * whenever a notification from the changelog is received. This should
 * add the object (or the gfid) on which the notification has come to
 * the timer-wheel with some expiry time.
 *
 * TODO: use mem-pool for allocations and maybe allocate timer and
 * object as a single alloc and bifurcate their respective pointers.
 */
void
br_brick_callback (void *xl, char *brick,
                   void *data, changelog_event_t *ev)
{
        xlator_t                *this   = NULL;
        uuid_t                   gfid   = {0, };
        struct gf_tw_timer_list *timer  = NULL;
        br_private_t            *priv   = NULL;
        br_object_t             *object = NULL;
        int                      ret    = -1;
        br_child_t              *child  = NULL;

        this = xl;
        priv = this->private;

        GF_ASSERT (ev->ev_type == CHANGELOG_OP_TYPE_RELEASE);
        uuid_copy (gfid, ev->u.release.gfid);

        GF_ASSERT ((uuid_is_null (gfid)) == 0);
        gf_log (this->name, GF_LOG_DEBUG,
                "got release event on gfid %s", uuid_utoa (gfid));

        if (ev->u.release.ordflags == O_RDONLY) {
                gf_log (this->name, GF_LOG_DEBUG, "read only fd (gfid: %s)",
                        uuid_utoa (gfid));
                goto out;
        }

        gf_log (this->name, GF_LOG_DEBUG, "flags: %d", ev->u.release.ordflags);

        timer = GF_CALLOC (1, sizeof (*timer), gf_common_mt_gf_timer_entry_t);
        if (!timer) {
                gf_log (this->name, GF_LOG_ERROR, "failed to allocate the "
                        "timer for expiry for the gfid %s",
                        uuid_utoa (gfid));
                goto out;
        }

        INIT_LIST_HEAD (&timer->entry);

        object = GF_CALLOC (1, sizeof (*object), gf_br_mt_br_object_t);
        if (!object) {
                gf_log (this->name, GF_LOG_ERROR, "failed to allocate the "
                        "memory for the object with the gfid %s",
                        uuid_utoa (gfid));
                goto out;
        }

        INIT_LIST_HEAD (&object->list);

        child = br_get_child_from_brick_path (this, brick);
        if (!child) {
                gf_log (this->name, GF_LOG_ERROR, "failed to get the subvolume "
                        "for the brick %s", brick);
                goto out;
        }

        object->this  = this;
        object->child = child;
        uuid_copy (object->gfid, gfid);
        object->signedversion = ev->u.release.opaque;

        timer->data     = object;
        timer->expires  = 60;
        timer->function = br_add_object_to_queue;
        gf_tw_add_timer (priv->timer_wheel, timer);

        gf_log (this->name, GF_LOG_DEBUG, "->callback: brick [%s], type [%d]\n",
                brick, ev->ev_type);

        ret = 0;

out:
        if (ret) {
                GF_FREE (timer);
                GF_FREE (object);
        }

        return;
}

void
br_fill_brick_spec (struct gf_brick_spec *brick, char *path)
{
        brick->brick_path = gf_strdup (path);
        brick->filter = CHANGELOG_OP_TYPE_RELEASE;

        brick->init         = br_brick_init;
        brick->fini         = br_brick_fini;
        brick->callback     = br_brick_callback;
        brick->connected    = NULL;
        brick->disconnected = NULL;
}

/**
 * This function gets the information about a child (or the corresponding
 * brick), such as brick path and the time at which the brick came up by
 * doing a lookup on the root first and then doing a getxattr (on a virtual
 * key). Then it registers with the changelog of that brick.
 *
 * TODO:
 * At this point a thread is spawned to crawl the filesystem (in tortoise
 * pace) to sign objects that were not signed in previous run(s). Such
 * objects are identified by examining it's dirtyness value and timestamp:
 *
 *    pick object:
 *       signature_is_stale() && (object_timestamp() <= stub_init_time())
 */
int32_t
br_brick_connect (xlator_t *this, br_child_t *child)
{
        int32_t                ret    = -1;
        loc_t                  loc    = {0, };
        struct iatt            buf    = {0, };
        struct iatt            parent = {0, };
        br_stub_init_t        *stub   = NULL;
        struct gf_brick_spec  *brick  = NULL;
        dict_t                *xattr  = NULL;

        GF_VALIDATE_OR_GOTO ("bit-rot", this, out);
        GF_VALIDATE_OR_GOTO (this->name, child, out);

        loc.inode = inode_ref (child->table->root);
        uuid_copy (loc.gfid, loc.inode->gfid);
        loc.path = gf_strdup ("/");

        ret = syncop_lookup (child->xl, &loc, NULL, &buf, NULL, &parent);
        if (ret) {
                gf_log (this->name, GF_LOG_ERROR, "lookup on root "
                        "failed (%s)", strerror (errno));
                goto out;
        }

        ret = syncop_getxattr (child->xl, &loc, &xattr,
                               GLUSTERFS_GET_BR_STUB_INIT_TIME, NULL);
        if (ret) {
                gf_log (this->name, GF_LOG_ERROR, "getxattr to get the brick "
                        "info for bit-rot failed (%s)", strerror (errno));
                goto out;
        }

        ret = dict_get_ptr (xattr, GLUSTERFS_GET_BR_STUB_INIT_TIME,
                            (void **)&stub);
        if (ret) {
                gf_log (this->name, GF_LOG_ERROR, "failed to get the brick "
                        "info");
                goto out;
        }

        brick = GF_CALLOC (1, sizeof (struct gf_brick_spec),
                           gf_common_mt_gf_brick_spec_t);
        if (!brick) {
                gf_log (this->name, GF_LOG_ERROR, "failed to allocate the "
                        "brick");
                errno = ENOMEM;
                goto out;
        }

        br_fill_brick_spec (brick, stub->export);
        memcpy (child->brick_path, stub->export, strlen (stub->export) + 1);

        ret = gf_changelog_register_generic ((struct gf_brick_spec *)brick, 1,
                                             1, "/dev/null", 0, this); /* set to 0 if
                                                                   ordering is not
                                                                   needed */
        if (ret) {
                gf_log (this->name, GF_LOG_ERROR, "failed tp connect to the "
                        "changelog of the brick %s (error: %s)",
                        brick->brick_path, strerror (errno));
                goto out;
        }

        ret = 0;

out:
        if (ret) {
                GF_FREE (brick->brick_path);
                GF_FREE (brick);
        }

        loc_wipe (&loc);
        if (xattr)
                dict_unref (xattr);

        return ret;
}

/**
 * This function is executed in a separate thread. The thread gets the
 * brick from where CHILD_UP has received from the queue and gets the
 * information regarding that brick (such as brick path).
 */
void *
br_handle_events (void *arg)
{
        xlator_t     *this  = NULL;
        br_private_t *priv  = NULL;
        br_child_t   *child = NULL;
        int32_t       ret   = -1;

        this = arg;
        priv = this->private;

        THIS = this;

        while (1) {
                pthread_mutex_lock (&priv->lock);
                {
                        while (list_empty (&priv->bricks)) {
                                pthread_cond_wait (&priv->cond,
                                                   &priv->lock);
                        }

                        child = list_entry (priv->bricks.next, br_child_t,
                                            list);
                        if (child && child->child_up) {
                                ret = br_brick_connect (this, child);
                                if (ret == -1)
                                        gf_log (this->name, GF_LOG_ERROR,
                                                "failed to connect to the "
                                                "child (subvolume: %s)",
                                                child->xl->name);
                                else
                                        list_del_init (&child->list);
                        }

                }
                pthread_mutex_unlock (&priv->lock);
        }

        return NULL;
}

int32_t
mem_acct_init (xlator_t *this)
{
        int32_t     ret = -1;

        if (!this)
                return ret;

        ret = xlator_mem_acct_init (this, gf_br_stub_mt_end + 1);

        if (ret != 0) {
                gf_log (this->name, GF_LOG_WARNING, "Memory accounting"
                        " init failed");
                return ret;
        }

        return ret;
}

int
notify (xlator_t *this, int32_t event, void *data, ...)
{
        xlator_t                *subvol = NULL;
        br_private_t            *priv   = NULL;
        int                      idx    = -1;
        br_child_t              *child  = NULL;

        subvol = (xlator_t *)data;
        priv = this->private;

        gf_log (this->name, GF_LOG_TRACE, "Notification received: %d",
                event);

        switch (event) {
        case GF_EVENT_CHILD_UP:
                /* should this be done under lock? or is it ok to do it
                   without lock? */
                idx = br_find_child_index (this, subvol);

                pthread_mutex_lock (&priv->lock);
                {
                        if (idx < 0) {
                                gf_log (this->name, GF_LOG_ERROR, "got child "
                                        "up from invalid subvolume");
                        } else {
                                child = &priv->children[idx];
                                if (child->child_up != 1)
                                        child->child_up = 1;
                                if (!child->xl)
                                        child->xl = subvol;
                                if (!child->table)
                                        child->table = inode_table_new (4096,
                                                                       subvol);
                                priv->up_children++;
                                list_add_tail (&child->list, &priv->bricks);
                                pthread_cond_signal (&priv->cond);
                        }
                }
                pthread_mutex_unlock (&priv->lock);
                break;

        case GF_EVENT_CHILD_MODIFIED:
                idx = br_find_child_index (this, subvol);
                if (idx < 0) {
                        gf_log (this->name, GF_LOG_ERROR, "received child up from "
                                "invalid subvolume");
                        goto out;
                }
                priv = this->private;
                //++(priv->generation);
                break;
        case GF_EVENT_CHILD_DOWN:
                idx = br_find_child_index (this, subvol);
                if (idx < 0) {
                        gf_log (this->name, GF_LOG_ERROR, "received child down from "
                                "invalid subvolume");
                        goto out;
                }

                pthread_mutex_lock (&priv->lock);
                {
                        if (priv->children[idx].child_up == 1) {
                                priv->children[idx].child_up = 0;
                                //destroy the rpc connection;
                                priv->up_children--;
                        }
                }
                pthread_mutex_unlock (&priv->lock);
                break;
        case GF_EVENT_PARENT_UP:
                default_notify (this, GF_EVENT_PARENT_UP, data);
                break;
        }

out:
        return 0;
}

int32_t
init (xlator_t *this)
{
	br_private_t *priv = NULL;
        int32_t   ret = -1;
        int       i = 0;
        xlator_list_t *trav = NULL;

	if (!this->children) {
		gf_log (this->name, GF_LOG_ERROR,
			"FATAL: no children");
		goto out;
	}

        priv = GF_CALLOC (1, sizeof (*priv), gf_br_mt_br_private_t);
        if (!priv)
                goto out;

        priv->child_count = xlator_subvolume_count (this);

        priv->children = GF_CALLOC (priv->child_count, sizeof (*priv->children),
                                    gf_br_mt_br_child_t);
        if (!priv->children) {
                gf_msg_nomem ("bit-rot", GF_LOG_ERROR, 555);
                ret = -ENOMEM;
                goto out;
        }

        trav = this->children;

        i = 0;
        while (trav) {
                priv->children[i].xl = trav->xlator;
                i++;
                trav = trav->next;
        }

        pthread_mutex_init (&priv->lock, NULL);
        pthread_cond_init (&priv->cond, NULL);

        for (i = 0; i < priv->child_count; i++)
                INIT_LIST_HEAD (&priv->children[i].list);

        INIT_LIST_HEAD (&priv->bricks);

	this->private = priv;

        this->local_pool = mem_pool_new (br_local_t, 128);
        if (!this->local_pool) {
                gf_log (this->name, GF_LOG_ERROR, "could not get mem pool for "
                        "frame->local");
                goto out;
        }

        priv->timer_wheel = gf_tw_init_timers ();
        if (!priv->timer_wheel) {
                gf_log (this->name, GF_LOG_ERROR, "failed to initialize the "
                        "timer wheel");
                goto out;
        }

        priv->obj_queue = GF_CALLOC (1, sizeof (*priv->obj_queue),
                                     gf_br_mt_br_ob_n_wk_t);
        if (!priv->obj_queue) {
                gf_log (this->name, GF_LOG_ERROR, "memory allocation failed");
                goto out;
        }

        INIT_LIST_HEAD (&priv->obj_queue->objects);

        ret = gf_thread_create (&priv->thread, NULL, br_handle_events,
                                this);
        if (ret != 0) {
                gf_log (this->name, GF_LOG_ERROR, "thread creation failed (%s)",
                        strerror (errno));
                goto out;
        }

        for (i = 0; i < BR_WORKERS; i++) {
                gf_thread_create (&priv->obj_queue->workers[i], NULL,
                                  br_process_object, this);
                if (ret != 0) {
                        gf_log (this->name, GF_LOG_ERROR, "thread creation "
                                "failed (%s)", strerror (errno));
                        goto out;
                }
        }

        ret = 0;

out:
        if (ret) {
                if (priv->children)
                        GF_FREE (priv->children);
                if (priv->timer_wheel)
                        gf_tw_cleanup_timers (priv->timer_wheel);
                GF_FREE (priv);
        }

        gf_log (this->name, GF_LOG_DEBUG, "bit-rot xlator loaded");
	return ret;
}

void
fini (xlator_t *this)
{
	br_private_t *priv = this->private;
        int           i    = 0;

        if (!priv)
                return;

        for (i = 0; i < priv->child_count; i++)
                list_del_init (&priv->children[i].list);

        GF_FREE (priv->children);
        this->private = NULL;
	GF_FREE (priv);

	return;
}

struct xlator_fops fops = {
        //.lookup = br_lookup,
};

struct xlator_cbks cbks;

struct volume_options options[] = {
	{ .key  = {NULL} },
};
