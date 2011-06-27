#!/usr/bin/python

import getopt
import sys, os

def usage():
    print "usage: python setup.py -u <remote user name> -j <glustefs jar> -h <hostname[s]]"\
        " -d <remote hadoop dir>"

def make_absolute_path (u, s):
    if (s[-1] == '/'):
        s = s[:-1]

    if (s[0] != '/'):
        s = '/' + u + '/' + s

    return s

def do_setup(options):
    opt = dict(options)

    user = opt['-u']
    jar_file = opt['-j']
    hostnames = opt['-h']
    remote_dir = opt['-d']

    if (os.path.exists(jar_file) == False):
        print 'jar file ' + jar_file + ' does not exist'
        return

    remote_dir = make_absolute_path (user, remote_dir)

    host_list = hostnames.split(',')
    for host in host_list:
        scp_cmd = 'scp ' + jar_file + ' ' + user + '@' + host + ':' + remote_dir + '/lib/'
        print 'Executing: ' + scp_cmd

        os.system (scp_cmd)

if __name__ == '__main__':
    opt = args = []
    try:
        opt,args = getopt.getopt(sys.argv[1:], 'u:j:h:d:')
    except getopt.GetoptError, err:
        usage()
        sys.exit(1)

    do_setup (opt)
