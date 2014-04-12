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
DEBUG = False
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
    global DEBUG
    ## Arguments
    args = sys.argv[1:]
    # Help    
    if 'help' in args or len(args) == 0:
        showHelp()
        return
    # Debug
    if 'debug' in args:
        DEBUG = True
    # Everything else
    if args[0] == 'sync':   # Sync with server (due to the way how CloudZec works it is not possible to just sync the client to the server or the other way round!)
        c = cloudzec.CloudZec(debug=DEBUG)
        c.sync()
    elif args[0] == 'init': # Only create an instanze of class CloudZec() and run __init__()
        c = cloudzec.CloudZec(genMasterKey=True, debug=DEBUG)
    #elif 'serverinit' == args[0]:       # Initialise server, setup files, pubkeys, history and allocation
    #    serverinit(conf, gpgHandler)
    #elif 'autoupload' == args[0]:       # Autoupload - watch for changes in CloudZec and sync them with the server (upload only)
    #    autoupload(conf, gpgHandler)
    else:
        print('Unknown argument „{}“'.format(args[0]))
        showHelp()
    ## Return
    return 0

if __name__ == '__main__':
    main()
