#!/usr/bin/env python3
# -*- coding: utf-8 -*-


## Readme | http://cloudzec.org/
#
# Inotify | python-pyinotify
#  https://github.com/seb-m/pyinotify
#


## Imports
import os
import sys

import cloudzec


## Data
DEBUG = True
BREAK = False


## Application

def showHelp():
    print('Possible arguments:\n')
    print('  help')
    print('   -> Shows this help\n')


def debug(text):
    if DEBUG:
        print('Debug: {}'.format(text))
    if BREAK:
        input('  Press ENTER to continue')


def main():
    ## Data
    c = cloudzec.CloudZec(debug=DEBUG)
    #cloud = Cloud(username='florian', password='~/.ssh/id_rsa', port=1337, fingerprint='5A5A3BDC', serverpath='/home/florian/cloudzec', genKeyFile=True, debug=True)

    ## Arguments
    args = sys.argv[1:]
    if 'help' in args or len(args) == 0:
        showHelp()
    elif args[0] == 'sync':     # Sync with server (due to the way how CloudZec works it is not possible to just sync the client to the server or the other way round!)
        c.sync()
    #elif 'serverinit' == args[0]:       # Initialise server, setup files, pubkeys, history and allocation
    #    serverinit(conf, gpgHandler)
    #elif 'autoupload' == args[0]:       # Autoupload - watch for changes in CloudZec and sync them with the server (upload only)
    #    autoupload(conf, gpgHandler)
    #elif args[0] == 'sync':             # Sync with the server
    #    c.sync()
    else:
        showHelp()
    ## Return
    return 0

if __name__ == '__main__':
    main()
