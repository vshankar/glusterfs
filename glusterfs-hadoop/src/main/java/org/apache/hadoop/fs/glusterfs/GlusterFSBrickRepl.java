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

public class GlusterFSBrickRepl {
        private String[] replHost;
        private long start;
        private long len;
        private int cnt;

        GlusterFSBrickRepl(int replCount, long start, long len) {
                this.replHost = new String[replCount];
                this.start = start;
                this.len = len;
                this.cnt = 0;
        }

        public void addHost (String host) {
                this.replHost[cnt++] = host;
        }

        public String[] getReplHosts () {
                return this.replHost;
        }

        public long getStartLen () {
                return this.start;
        }

        public long getOffLen () {
                return this.len;
        }
}