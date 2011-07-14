#!/usr/bin/python

import getopt
import glob
import sys, os
import shutil
import subprocess, shlex

def usage():
    print "usage: python deploy-jar.py [-b] -d <hadoop-home>"

def addSlash(s):
    if not (s[-1] == '/'):
        s = s + '/'

    return s

def whereis(program):
    abspath = None
    for path in (os.environ.get('PATH', '')).split(':'):
        abspath = os.path.join(path, program)
        if os.path.exists(abspath) and not os.path.isdir(abspath):
            return abspath

    return None

def getLatestJar(targetdir):
    latestJar = None
    glusterfsJar = glob.glob(targetdir + "*.jar")
    if len(glusterfsJar) == 0:
        print "No GlusterFS jar file found in %s ... exiting" % (targetdir)
        return None

    # pick up the latest jar file - just in case ...
    stat = latestJar = None
    ctime = 0

    for jar in glusterfsJar:
        stat = os.stat(jar)
        if stat.st_ctime > ctime:
           latestJar = jar
           ctime = stat.st_ctime

    return latestJar

# build the glusterfs hadoop plugin using maven
def build_jar():
    location = whereis('mvn')

    if location == None:
        print "Cannot find maven to build glusterfs hadoop jar"
        print "please install mavem or if it's already installed then fix PATH environ"
        return None

    # do a clean packaging
    targetdir = "./target/"
    if os.path.exists(targetdir) and os.path.isdir(targetdir):
        print "Cleaning up directories ... [ " + targetdir + " ]"
        shutil.rmtree(targetdir)

    print "Building glusterfs jar ..."
    process = subprocess.Popen(['package'], shell=True,
                               executable=location, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        (pout, perr) = process.communicate()
    except:
        process.wait()
        if not process.returncode == 0:
            print "Building glusterfs jar failed"
            return None

    latestJar = getLatestJar(targetdir)
    return latestJar

def rcopy(jar, host, libdir):
    print "   * doing remote copy to host %s" % (host)
    scpCmd = "scp %s %s:%s" % (jar, host, libdir)

    os.system(scpCmd);

def deployInSlave(jar, confdir, libdir):
    slavefile = confdir + "slaves"

    f = open(slavefile, 'r')
    for host in f:
        host = host.rstrip('\n')
        print "  >>> Deploying jar on %s ..." % (host)
        rcopy(jar, host, libdir)

def deployInMaster(jar, confdir, libdir):
    import socket
    masterfile = confdir + "masters"

    f = open(masterfile, 'r')
    for host in f:
        host = host.rstrip('\n')
        print "  >>> Deploying jar on %s ..." % (host)
        h = host
        try:
            socket.inet_aton(host)
            h = socket.getfqdn(host)
        except socket.error:
            # host is not a ip adddress
            pass

        if h == socket.gethostname() or h == 'localhost':
            # local cp
            print "   * doing local copy"
            shutil.copy(jar, libdir)
        else:
            # scp the file
            rcopy(jar, h, libdir)

if __name__ == '__main__':
    opt = args = []
    try:
        opt, args = getopt.getopt(sys.argv[1:], "bd:");
    except getopt.GetoptError, err:
        usage()
        sys.exit(1)

    opt = dict(opt)

    if opt.get('-b') is not None:
        jar = build_jar()
        if jar == None:
            sys.exit(1)
    else:
        jar = getLatestJar('./target/')
        if jar == None:
            print "Maybe you want to build it ? -b option"
            sys.exit(1)

    print ""
    print "*** Deploying %s *** " % (jar)

    # copy jar to local hadoop distribution (master)
    hadoop_home = addSlash(opt['-d'])
    if not (os.path.exists(hadoop_home) and os.path.isdir(hadoop_home)):
        print "path " + hadoop_home + " does not exist or is not adiretory";
        sys.exit(1);

    hadoop_conf = hadoop_home + "conf/"
    hadoop_lib = hadoop_home + "lib/"

    print " >>> Scanning hadoop master file for host(s) to deploy"
    deployInMaster(jar, hadoop_conf, hadoop_lib)

    print ""
    print " >>> Scanning hadoop slave file for host(s) to deploy"
    deployInSlave(jar, hadoop_conf, hadoop_lib)
