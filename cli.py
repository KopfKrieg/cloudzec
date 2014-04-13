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
# External
import cloudzec


## Application
def showHelp():
    print('Possible arguments:\n')
    print('  help')
    print('   -> Shows this help\n')
    print('  init')
    print('   -> Initialise CloudZec sync\n')
    print('  sync')
    print('   -> Full sync between server and client\n')
    print('  debug')
    print('   -> At this at the end of any other command to get debug-output')
    print('    -> cli.py init debug')
    print('    -> cli.py sync debug')
    print()


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
    if args[0] == 'sync':   # Sync with server
        c = cloudzec.CloudZec(debug=DEBUG)
        c.sync()
    elif args[0] == 'init': # Only create an instanze of class CloudZec() and run __init__()
        c = cloudzec.CloudZec(genMasterKey=True, debug=DEBUG)
    #elif 'serverinit' == args[0]:       # Initialise server and create a basic setup
    #    c = cloudzec.CloudZec(debug=DEBUG)
    #    c.serverinit()
    else:
        print('Unknown argument „{}“'.format(args[0]))
        showHelp()
    ## Return
    return 0

if __name__ == '__main__':
    main()
