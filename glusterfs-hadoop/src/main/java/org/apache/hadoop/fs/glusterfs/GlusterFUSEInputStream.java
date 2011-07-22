/*
  Copyright (c) 2010 Gluster, Inc. <http://www.gluster.com>
  This file is part of GlusterFS.

  GlusterFS is GF_FREE software; you can redistribute it and/or modify
  it under the terms of the GNU Affero General Public License as published
  by the Free Software Foundation; either version 3 of the License,
  or (at your option) any later version.

  GlusterFS is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Affero General Public License for more details.

  You should have received a copy of the GNU Affero General Public License
  along with this program.  If not, see
  <http://www.gnu.org/licenses/>.

  @author: Venky Shankar (venky@gluster.com)
*/

package org.apache.hadoop.fs.glusterfs;

import java.io.*;
import java.util.TreeMap;

import org.apache.hadoop.fs.FSInputStream;
import org.apache.hadoop.fs.FileSystem;


public class GlusterFUSEInputStream extends FSInputStream {
        File                                  f;
        boolean                               lastActive;
        long                                  pos;
        boolean                               closed;
        String                                thisHost;
        RandomAccessFile                      fuseInputStream;
        RandomAccessFile                      fsInputStream;
        GlusterFSBrickClass                   thisBrick;
        int                                   nodeLocation;
        TreeMap<Integer, GlusterFSBrickClass> hnts;

        public GlusterFUSEInputStream (File f, TreeMap<Integer, GlusterFSBrickClass> hnts,
                                       String hostname) throws IOException {
                this.f = f;
                this.pos = 0;
                this.closed = false;
                this.hnts = hnts;
                this.thisHost = hostname;
                this.fsInputStream = null;
                this.fuseInputStream = new RandomAccessFile(f.getPath(), "r");

                this.lastActive = true; // true == FUSE, false == backed file

                String directFilePath = null;
                if (this.hnts != null) {
                        directFilePath = findLocalFile(f.getPath(), this.hnts);
                        if (directFilePath != null) {
                                this.fsInputStream = new RandomAccessFile(directFilePath, "r");
                                this.lastActive = !this.lastActive;
                        }
                }
        }

        public String findLocalFile (String path, TreeMap<Integer, GlusterFSBrickClass> hnts) {
                int i = 0;
                String actFilePath = null;
                GlusterFSBrickClass gfsBrick = null;

                gfsBrick = hnts.get(0);

                /* do a linear search for the matching host not worrying
                   about file stripes */
                for (i = 0; i < hnts.size(); i++) {
                        gfsBrick = hnts.get(i);
                        actFilePath = gfsBrick.brickIsLocal(this.thisHost);
                        if (actFilePath != null) {
                                this.thisBrick = gfsBrick;
                                this.nodeLocation = i;
                                break;
                        }
                }

                return actFilePath;
        }

        public long getPos () throws IOException {
                return pos;
        }

        public synchronized int available () throws IOException {
                return (int) ((f.length()) - getPos());
        }

        public void seek (long pos) throws IOException {
                fuseInputStream.seek(pos);
                if (fsInputStream != null)
                        fsInputStream.seek(pos);
        }

        public boolean seekToNewSource (long pos) throws IOException {
                return false;
        }

        public RandomAccessFile chooseStream (long start, int[] nlen) {
                GlusterFSBrickClass gfsBrick = null;
                RandomAccessFile in = fuseInputStream;
                lastActive = true;

                if ((hnts != null) && (fsInputStream != null)) {
                        gfsBrick = hnts.get(0);
                        if (!gfsBrick.isChunked()) {
                                in = fsInputStream;
                                lastActive = false;
                        } else {
                                // find the current location in the tree and the amount of data it can serve
                                int[] nodeInTree = thisBrick.getBrickNumberInTree(start, nlen[0]);

                                // does this node hold the byte ranges we have been requested for ?
                                if ((nodeInTree[2] != 0) && thisBrick.brickHasFilePart(nodeInTree[0], nodeLocation)) {
                                        in = fsInputStream;
                                        nlen[0] = nodeInTree[2]; // the amount of data that can be read from the stripe
                                        lastActive = false;
                                }
                        }
                }

                return in;
        }

        public synchronized int read () throws IOException {
                int byteRead = 0;
                RandomAccessFile in = null;

                if (closed)
                        throw new IOException("Stream Closed.");

                int[] nlen = { 1 };

                in = chooseStream(getPos(), nlen);
                byteRead = in.read();
                if (byteRead > 0) {
                        pos++;
                        syncStreams(pos);
                }

                return byteRead;
        }

        public synchronized int read (byte buff[], int off, int len) throws
                IOException {
                int result = 0;
                RandomAccessFile in = null;

                if (closed)
                        throw new IOException("Stream Closed.");

                int[] nlen = {len}; // hack to make len mutable
                in = chooseStream(pos+off, nlen);

                result = in.read(buff, off, nlen[0]);
                if (result > 0) {
                        pos += result;
                        syncStreams(pos);
                }

                return result;
        }

        public void syncStreams (long pos) throws IOException {
                if ((hnts != null) && (hnts.get(0).isChunked()) && (fsInputStream != null))
                        if (!this.lastActive)
                                fuseInputStream.seek(pos);
                        else
                                fsInputStream.seek(pos);
        }

        public synchronized void close () throws IOException {
                if (closed)
                        throw new IOException("Stream closed.");

                super.close();
                if (fsInputStream != null)
                        fsInputStream.close();
                fuseInputStream.close();

                closed = true;
        }

        // Not supported - mark () and reset ()

        public boolean markSupported () {
                return false;
        }

        public void mark (int readLimit) {}

        public void reset () throws IOException {
                throw new IOException("Mark/Reset not supported.");
        }
}