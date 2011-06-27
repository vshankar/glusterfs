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

import org.apache.hadoop.fs.FSOutputSummer;
import org.apache.hadoop.fs.FileSystem;

public class GlusterFUSEOutputStream extends OutputStream {
        File         f;
        long         pos;
        boolean      closed;
        OutputStream fuseOutputStream;

        public GlusterFUSEOutputStream (String file, boolean append) throws
                IOException {
                this.f = new File(file); /* not needed ? */
                this.pos = 0;
                this.fuseOutputStream = new FileOutputStream(file, append);
                this.closed = false;
        }

        public long getPos () throws IOException {
                return pos;
        }

        public void write (int v) throws IOException {
                if (closed)
                        throw new IOException("Stream closed.");

                byte[] b = new byte[1];
                b[0] = (byte) v;

                write(b, 0, 1);
        }

        public void write (byte b[]) throws IOException {
                if (closed)
                        throw new IOException("Stream closed.");

                fuseOutputStream.write(b, 0, b.length);
        }

        public void write (byte b[], int off, int len) throws IOException {
                if (closed)
                        throw new IOException("Stream closed.");

                fuseOutputStream.write(b, off, len);
                pos += (long) len;
        }

        public void flush () throws IOException {
                if (closed)
                        throw new IOException("Stream closed.");

                fuseOutputStream.flush();
        }

        public void close () throws IOException {
                if (closed)
                        throw new IOException("Stream closed.");

                flush();
                fuseOutputStream.close();
                closed = true;
        }
}

