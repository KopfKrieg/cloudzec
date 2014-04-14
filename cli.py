#!/usr/bin/env python3
# -*- coding: utf-8 -*-


## Readme | http://cloudzec.org/
#

## Imports
import os
import sys
# External
import cloudzec


## Data
DEBUG = False


## Application
def showHelp():
    print('Possible arguments:\n')
    print('  help')
    print('   -> Shows this help\n')
    print('  init')
    print('   -> Initialise the local repository\n')
    print('  remoteinit')
    print('   -> Initialise the remote repository\n')
    print('  sync')
    print('   -> Full sync between remote and local repository\n')
    print('  daemon x')
    pritn('   -> Full sync between remote and local repository, „x“ is the time between syncs in minutes or 15 minutes if not given\n')
    print('  debug')
    print('   -> At this at the end of any other command to get debug-output')
    print('    -> cli.py init debug')
    print('    -> cli.py sync debug')
    print()


def debug(text):
    if DEBUG:
        print('Debug: {}'.format(text))


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
    if args[0] == 'init':           # Local init
        c = cloudzec.CloudZec(genMasterKey=True, debug=DEBUG)
    elif args[0] == 'remoteinit':   # Remote init
        c = cloudzec.CloudZec(debug=DEBUG)
        c.remoteinit()
    elif args[0] == 'sync':         # Sync remote <-> local
        c = cloudzec.CloudZec(debug=DEBUG)
        c.sync()
    elif args[0] == 'daemon':       # Sync remote <-> local in daemon mode
        # Parse time
        import time
        t = 15
        if len(args) > 1:
            if args[1].isdigit():
                t = int(args[1])
        debug('Daemon mode with an interval of {} minutes'.format(t))
        # Setup and run
        c = cloudzec.CloudZec(debug=DEBUG)
        while True:
            c.sync()
            debug('Sleeping for {} minutes'.format(t))
            time.sleep(t*60)
    else:
        print('Unknown argument „{}“'.format(args[0]))
        showHelp()
    ## Return
    return 0


if __name__ == '__main__':
    main()
