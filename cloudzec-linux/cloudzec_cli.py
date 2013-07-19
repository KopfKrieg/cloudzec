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

import cloud


## Data
DEBUG = True
BREAK = False


## Application

def showHelp():
    print('Possible arguments:\n')
    print('  help')
    print('   -> Shows this help\n')
    #print('  put $file')
    #print('   -> Upload $file to server\n')
    #print('  get $file')
    #print('   -> Download $file from server\n')
    #print('  history')
    #print('   -> Get history from server\n')
    #print('  update')
    #print('   -> Sync with server (nothing is removed, only downloaded)\n')
    #print('  serverinit')
    #print('   -> Setup server if not already done)\n')


#def ask(typ, question):
#    from gi.repository import Notify
#    Notify.init('CloudZec')
#    # optionally set an icon as the last argument
#    n = Notify.Notification.new('CloudZec', 'Hm, CloudZec wants to know something...', None)
#    n.show()
#    #n.close()
#    Notify.uninit()
#    return input(question)


def debug(text):
    if DEBUG:
        print('Debug: {}'.format(text))
    if BREAK:
        input('  Press ENTER to continue')


def main():
    ## Data
    home = os.path.expanduser('~') #os.getenv('HOME') There is no $HOME on Windows
    confFolder = os.path.join(home, '.cloudzec')
    confFile = os.path.join(confFolder, 'cloudzec.conf')
    c = cloud.CloudZec(debug=DEBUG)
    #cloud = Cloud(username='florian', password='~/.ssh/id_rsa', port=1337, fingerprint='5A5A3BDC', serverpath='/home/florian/cloudzec', genKeyFile=True, debug=True)

    ## Arguments
    args = sys.argv[1:]
    if 'help' in args or len(args) == 0:
        showHelp()
        return 0
    #elif 'serverinit' == args[0]:       # Initialise server, setup files, pubkeys, history and allocation
    #    serverinit(conf, gpgHandler)
    #elif 'autoupload' == args[0]:       # Autoupload - watch for changes in CloudZec and sync them with the server (upload only)
    #    autoupload(conf, gpgHandler)
    elif args[0] == 'sync':             # Sync with the server
        c.sync()
    else:
        showHelp()
    ## Return
    return 0

if __name__ == '__main__':
    main()
