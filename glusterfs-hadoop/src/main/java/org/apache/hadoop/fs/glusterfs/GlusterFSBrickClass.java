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

public class GlusterFSBrickClass {
        String  host;
        String  exportedFile;
        long    start;
        long    end;
        boolean isChunked;
        int     stripeSize;     // Stripe size in bytes
        int     nrStripes;      // number of stripes
        int     switchCount;    // for SR, DSR - number of replicas of each stripe
                                // -1 for others

        public GlusterFSBrickClass (String brick, long start, long len, boolean flag,
                                    int stripeSize, int nrStripes, int switchCount)
                throws IOException {
                this.host = brick2host(brick);
                this.exportedFile = brick2file(brick);
                this.start = start;
                this.end = start + len;
                this.isChunked = flag;
                this.stripeSize = stripeSize;
                this.nrStripes = nrStripes;
                this.switchCount = switchCount;
        }

        public boolean isChunked () {
                return isChunked;
        }

        public String brickIsLocal(String hostname) {
                String path = null;
                File f = null;
                if (host.equals(hostname))
                        path = exportedFile;

                return path;
        }

        public int[] getBrickNumberInTree(long start, int len) {
                long end = len;
                int startNodeInTree = ((int) (start / stripeSize)) % nrStripes;
                int endNodeInTree = ((int) ((start + len) / stripeSize)) % nrStripes;

                if (startNodeInTree != endNodeInTree) {
                        end = (start - (start % stripeSize)) + stripeSize;
                        end -= start;
                }

                return new int[] {startNodeInTree, endNodeInTree, (int) end};
        }

        public boolean brickHasFilePart(int nodeInTree, int nodeLoc) {
                if (switchCount == -1)
                        return (nodeInTree == nodeLoc);

                nodeInTree *= switchCount;
                for (int i = nodeInTree; i < (nodeInTree + switchCount); i++) {
                        if (i == nodeLoc)
                                return true;
                }

                return false;
        }

        public String brick2host (String brick)
                throws IOException {
                String[] hf = null;

                hf = brick.split(":");
                if (hf.length != 2)
                        throw new IOException("Error getting hostname from brick");

                return hf[0];
        }

        public String brick2file (String brick)
                throws IOException {
                String[] hf = null;

                hf = brick.split(":");
                if (hf.length != 2)
                        throw new IOException("Error getting hostname from brick");

                return hf[1];
        }

}