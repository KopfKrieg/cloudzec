#!/usr/bin/env python3
# -*- coding: utf-8 -*-


## Readme | http://cloudzec.org/
#
# This is the basic CloudZec client with command line interface
# 
#
# GnuPG | python-gnupg
#  http://code.google.com/p/python-gnupg/
#  http://pythonhosted.org/python-gnupg/
#
# Paramiko | python-paramiko
#  https://github.com/paramiko/paramiko
#  https://github.com/paramiko/paramiko/issues/16
#  https://github.com/nischu7/paramiko
#


## Imports
# Internal
import os
import sys
import json
import getpass
# External
import gnupg
import paramiko


## Data
DEBUG = True
BREAK = False


## Classes


## Application

def checkKey(gpg, fingerprint):
    '''Needs an 8 digit long fingerprint and returns True if valid and False if not'''
    fingerprints = []
    for key in gpg.list_keys():
        fingerprints.append(key['keyid'][-8:])
    if fingerprint in fingerprints:
        return True
    return False


def writeConf(confFile, conf, _debug=True):
    with open(confFile, 'w') as f:
        f.write(json.dumps(conf, indent=2, sort_keys=True))
        if _debug:
            debug('Write configuration file: {}'.format(confFile))


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


def debug(text):
    if DEBUG:
        print('Debug: {}'.format(text))
    if BREAK:
        input('  Press ENTER to continue')


def main():
    ## Data
    home = os.getenv('HOME') #os.path.expanduser('~')
    confFolder = os.path.join(home, '.cloudzec')
    confFile = os.path.join(confFolder, 'cloudzec.conf')
    conf = None
    defaultConf = {'name'       : None,                             # Alias for this machine
                   'host'       : 'cloudzec.org',                   # Host to connect, either domain or ip address
                   'port'       : '22',                             # Port to connect
                   'username'   : None,                             # Username for server login
                   'password'   : None,                             # Type of password. None means password, a path means identity-file
                   'serverpath' : None,                             # Path on server, default: /home/user/cloudzec
                   'fingerprint': None,                             # Fingerprint of gpg keys
                   'syncfolder' : os.path.join(home, 'CloudZec'),   # Local sync-folder
                   'cache'      : os.path.join(confFolder, 'cache') # Local cache-folder
                  }
    gpgHandler = gnupg.GPG()
    ## Check conf
    # Create confFolder if missing
    if not os.path.exists(confFolder):
        os.makedirs(confFolder)
        debug('  Create confFolder {}'.format(confFolder))
    # Create confFile if missing
    if not os.path.exists(confFile):
        writeConf(confFile, defaultConf, False)
        debug('  Create confFile {}'.format(confFile))
    # Read and check confFile
    with open(confFile, 'r') as f:
        conf = json.load(f)
        rewrite = False
        # Missing keys
        for key in defaultConf:
            if not key in conf:
                rewrite = True
                conf[key] = defaultConf[key]
                debug('Add missing key: {}'.format(key))
        # Unnecessary keys
        tmpConf = conf.copy()
        for key in tmpConf:
            if not key in defaultConf:
                rewrite = True
                del conf[key]
                debug('Remove unnecessary key: {}'.format(key))
        # Rewrite if needed
        if rewrite:
            writeConf(confFile, conf)
            debug('  Rewrite conf')
    ## Check files and folders in config
    # Check folder: cache
    if not os.path.exists(conf['cache']):
        os.makedirs(conf['cache'])
        debug('Create folder: {}'.format(conf['cache']))
    # Check folder: syncfolder
    if not os.path.exists(conf['syncfolder']):
        os.makedirs(conf['syncfolder'])
        debug('Create folder: {}'.format(conf['syncfolder']))
    # Check name, username, serverpath and fingerprint
    rewrite = False
    # name
    if conf['name'] is None:
        conf['name'] = input('Please set a name for this device: ')
        rewrite = True
    # username
    if conf['username'] is None:
        conf['username'] = input('Please set your username for server access: ')
        rewrite = True
    # serverpath
    if conf['serverpath'] is None:
        conf['serverpath'] = os.path.join('/home', conf['username'], 'cloudzec')
        rewrite = True
    # fingerprint
    while not checkKey(gpgHandler, conf['fingerprint']):
        i = 0
        fingerprints = []
        print('Choose your key:')
        for key in gpgHandler.list_keys():
            fingerprints.append(key['keyid'][-8:])
            print('  {}.\t{} {}'.format(i, key['keyid'][-8:], key['uids'][0]))
            i += 1
        print('  {}.\tGenerate new key pair'.format(i))
        choice = int(input())
        if choice == i:
            keySize = 2048
            keyType = 'RSA'
            expireDate = input('Expire date? (Input like „2014-08-01“, „5y“, „365d“, „3m“ or “6w”, „0“ for non-expire) ')
            password = getpass.getpass('Optional password for GPG-key? ')
            print('GPG-keys will now be generated. You should produce as much entropy as possible. Write a text, move the mouse, surf the web (something like that). It will improve the security')
            print('Oh, and this may take a while :)')
            input_data = gpgHandler.gen_key_input(key_type=keyType, key_length=keySize, name_real='CloudZec', name_comment='Autogenerated key for CloudZec', subkey_type=keyType, subkey_length=keySize, expire_date=expireDate, passphrase=password)
            gpgHandler.gen_key(input_data)
        else:
            conf['fingerprint'] = fingerprints[choice]
        rewrite = True
    # Rewrite if needed
    if rewrite:
        writeConf(confFile, conf)
        debug('  Rewrite conf')
    ## Setup everything else that is needed
    transport = None
    sftpHandler = None

    ## Arguments
    args = sys.argv[1:]
    if 'help' in args or len(args) == 0:
        showHelp()
        return 0
    elif 'serverinit' == args[0]:       # Initialise server, setup files, pubkeys, history and allocation
        # Login
                 
        # Create lock if not existent (and if lock exists, quit)

        # Create cloudzec, files and pubkeys folder

        # Create empty history

        # Create emmpty allocation

        # Upload pubkey

        # Remove lock

        # Logout

        pass
    elif '' == args[0]:
        pass
    elif '' == args[0]:
        pass
    elif '' == args[0]:
        pass
    elif '' == args[0]:
        pass
    else:
        showHelp()





    ## Return
    return 0

if __name__ == '__main__':
    main()
