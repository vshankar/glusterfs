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

import org.apache.hadoop.fs.FSInputStream;
import org.apache.hadoop.fs.FileSystem;

public class GlusterFUSEInputStream extends FSInputStream {
        File                  f;
        private long          pos;
        private boolean       closed;
        InputStream           fuseInputStream;

        public GlusterFUSEInputStream (File f) throws IOException {
                this.f = f;
                this.pos = 0;
                this.closed = false;
                this.fuseInputStream = new FileInputStream(f.getPath());
        }

        public long getPos () throws IOException {
                return pos;
        }

        public synchronized int available () throws IOException {
                return (int) ((f.length()) - pos);
        }

        public void seek (long pos) throws IOException {
                System.out.println("Seeking to position " + pos);
                fuseInputStream.skip(pos);
        }

        public boolean seekToNewSource (long pos) throws IOException {
                return false;
        }

        public synchronized int read () throws IOException {
                int byteRead = 0;

                if (closed)
                        throw new IOException("Stream Closed.");

                byteRead = fuseInputStream.read();
                if (byteRead >= 0)
                        pos++;

                return byteRead;
        }

        public synchronized int read (byte buff[], int off, int len) throws
                IOException {

                int result = 0;

                if (closed)
                        throw new IOException("Stream Closed.");

                result = fuseInputStream.read(buff, off, len);
                if (result > 0)
                        pos += result;

                return result;
        }

        public synchronized void close () throws IOException {
                if (closed)
                        throw new IOException("Stream closed.");

                super.close();
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