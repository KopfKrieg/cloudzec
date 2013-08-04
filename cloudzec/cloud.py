#!/usr/bin/env python3
# -*- coding: utf-8 -*-


## Readme | http://cloudzec.org
#
# This is the basic CloudZec Class
#
# Note to myself: First compress, then encrypt
#               : First remove, then add
#               : Hash is generated with „path+hashofFile“: „sha256('folder/file.txtdf870a68df70a86df076adf45a60d4f6a5')“, this makes sure every file includings its (relative) uri is really unique
#
#
## Compression | TarFile | Maybe no compression because compression could be too slow for large files with no benefit
#  http://docs.python.org/3.3/library/tarfile.html
#  http://docs.python.org/3.3/library/archiving.html
#
## GnuPG | python-gnupg fork | Fast development, including security patches, etc.
#  https://github.com/isislovecruft/python-gnupg/
#  https://python-gnupg.readthedocs.org/en/latest/gnupg.html#gnupg-module
#
## GnuPG | python-gnupg | very slow development, security patches?
#  http://code.google.com/p/python-gnupg/
#  http://pythonhosted.org/python-gnupg/
#
## GnuPG | pygpgme | There's a lack of documentation so i won't use it at the moment
#  https://aur.archlinux.org/packages/pygpgme/
#  https://code.launchpad.net/~jamesh/pygpgme/trunk
#  http://pastebin.com/F1BY5vVR
#
## Paramiko | python-paramiko
#  https://github.com/paramiko/paramiko
#  https://github.com/paramiko/paramiko/issues/16
#  https://github.com/nischu7/paramiko
#  https://github.com/revogit/paramiko
#
## GnuPG | Options
# encryption:
#  gpg
#   --armor          ASCII armored output
#   --symmetric      Symmetric encryption using passphrase, may be combined with --sign
#   --cipher-algo    Specify cipher algorithm
#    aes256           using AES256 encryption
#   --output         Write output to a file
#    fout             The file
#   --batch          Batch mode, don't ask for anything, do not allow interactive commands, needed for --passphrase
#   --passphrase     Use string as the passphrase
#     pw              The passphrase
#   (--no-tty         Make sure that the TTY is never used for any output)
#   fin              The input file
# decryption:
#  gpg
#   --decrypt        Decrypt file
#   --output         Write output to a file
#    fout             The file
#   --batch          Batch mode, don't ask for anything, do not allow interactive commands, needed f$
#   --passphrase     Use string as the passphrase
#     pw              The passphrase
#   (--no-tty         Make sure that the TTY is never used for any output)
#   fin              The input file
#
#
## Server structure
# $serverpath
#  .
#  |-- alloc.conf
#  |-- files
#  |-- history
#  `-- pubkeys
#
## Local structure
# $syncfolder
# $confFolder
#  .
#  |-- alloc.conf
#  |-- cache
#  |   |-- download
#  |   `-- upload
#  |-- cloudzec.conf
#  |-- history.log
#  `-- key
#
## alloc.conf | Every file is packaged and compressed, so user rights, name, path, etc. can be restored (uri is still needed for syncToServer() in removing an item) | encrypted with masterkey
#  {
#    "hash1":["key1", "folder/file1"],
#    "hash2":["key2", "folder/file2"],
#    "hash3":["key3", "folder/file3"],
#    "hash4":["key4", "folder/file4"],
#    "hash5":["key5", "folder/file5"],
#    "hash6":["key6", "folder/file6"],
#    "hash7":["key7", "folder/file7"],
#    "hash8":["key8", "folder/file8"],
#    "hash9":["key9", "folder/file9"]
# }
#
## history | encrypted with masterkey
# +123456789.sha256     # File added
# +123789456.sha256     # File added
# -123456789.sha256     # File removed
# ?123789456.sha256 789456123.sha256    # First file gets replaced by second file
#
## history2 | encrypted with masterkey, new layout
# Unix timestamp filename   # From import time; time.time()
#
# 1387281434 +123456789     # File added
# 1387281442 +123789456     # File added
# 1387281485 -123456789     # File removed
#
# Not yet supported:
## 1387281442 ?123789456 789456123    # First file gets replaced by second file
#


## Imports
import os
import json
#import shutil
#import string
import random
#import getpass
import hashlib
import tarfile
import platform
#import subprocess

import gnupg
import paramiko


## Classes
class CloudZec:
    def __init__(self, username=None, identFile=None, host='cloudzec.org', port=22, fingerprint=None, serverpath=None, allocSync=True, genMasterKey=True, debug=False):
        ## Basic setup
        # Data
        home = os.path.expanduser('~')
        self.confFolder = os.path.join(home, '.cloudzec')
        self.confFile = os.path.join(self.confFolder, 'cloudzec.conf')
        self._debug = debug
        # Default configuration, use loadConfiguration() to override
        self.device = platform.node()        # Device name
        self.username = username    # Username for login to server
        self.identFile = identFile  # Identify file for serverlogin, None if passwordlogin is preferred over publickey
        self.host = host            # Server/Host
        self.port = port            # Server port
        self.cache = os.path.join(self.confFolder, 'cache')
        self.cacheUp = os.path.join(self.confFolder, 'cache', 'upload')
        self.cacheDown = os.path.join(self.confFolder, 'cache', 'download')
        self.historyFile = os.path.join(self.confFolder, 'history.log')     # Local history
        self.allocationFile = os.path.join(self.confFolder, 'alloc.conf')   # Allocation file, JSON format
        self.keyFile = os.path.join(self.confFolder, 'key')                 # Key file with masterkey
        self.fingerprint = fingerprint  # Fingerprint of gpg key (used for masterkey en/decryption
        self.syncfolder = os.path.join(home, 'CloudZec')# Local sync-folder
        self.serverpath = serverpath    # Path on server
        self.allocSync = allocSync      # If true, allocation will be synced
        self.masterKey = None           # Masterkey for alloc.conf en/decryption
        self.compression = 'bzip2'      # Preferred compression algorithm |lzma: slow compress, small file, very fast decompress |bzip2: fast compress, small file, fast decompress |gzip: big file, very fast compress, very fast decompress |Choose wisely
        self.encryption = 'AES256'      # Preferred encryption algorithm
        self.allocation = {}
        # Create confFolder if missing
        if not os.path.exists(self.confFolder):
            self.debug('Create confFolder {}'.format(self.confFolder))
            os.makedirs(self.confFolder)
        # Load configuration (and override defaults)
        self.loadConfiguration()
        ## Check configuration
        rewrite = False
        # Check folder: cache
        if not os.path.exists(self.cache):
            self.debug('Create folder: {}'.format(self.cache))
            os.makedirs(self.cache)
        # Check folder: cacheUp
        if not os.path.exists(self.cacheUp):
            self.debug('Create folder: {}'.format(self.cacheUp))
            os.makedirs(self.cacheUp)
        # Check folder: cacheDown
        if not os.path.exists(self.cacheDown):
            self.debug('Create folder: {}'.format(self.cacheDown))
            os.makedirs(self.cacheDown)
        # Check folder: syncfolder
        if not os.path.exists(self.syncfolder):
            self.debug('Create folder: {}'.format(self.syncfolder))
            os.makedirs(self.syncfolder)
        # Check username
        if self.username is None:
            raise Exception('You need to set a username in {}'.format(self.confFile))
            # Don't ask anything in __init__()
            #self.debug('Ask for username')
            #self.username = self.ask('Username for server login: ', 'str')
            #rewrite = True
        # Check serverpath | path like /home/$username/cloudzec on the server!
        if self.serverpath is None:
            self.debug('Create default serverpath')
            self.serverpath = os.path.join('/home', self.username, 'cloudzec')
            rewrite = True
        # Rewrite if needed
        if rewrite:
            self.storeConfiguration()
        # Create gpg instance | needs to be defined before history and allocation check
        binary = '/usr/bin/gpg2' # No symlinks allowed
        homedir = os.path.join(home, '.gnupg')
        #keyring = os.path.join(homedir, 'pubring.gpg')
        #secring = os.path.join(homedir, 'secring.gpg')
        #self.gpg = gnupg.GPG(binary=binary, homedir=homedir, keyring=keyring, secring=secring)
        self.gpg = gnupg.GPG(binary=binary, homedir=homedir)
        #self.gpg.use_agent = True
        ## Load master key | Needs to be done before storing something (encrypted)
        self.loadMasterKey(genMasterKey)
        # Check history, create empty file if not present
        if not os.path.exists(self.historyFile):
            self.debug('Create empty history')
            self.history = []
            self.storeClientHistory()
        #else:
        #    self.loadClientHistory()
        # Check allocation, create empty file if not present
        if not os.path.exists(self.allocationFile):
            self.debug('Create empty allocation')
            self.allocation = {}
            self.storeClientAllocation()
        #else:
        #    self.loadClientAllocation()
        # Rewrite?
        if rewrite:
            self.debug('Rewrite configuration')
            self.storeConfiguration()


    def loadConfiguration(self):
        """
        Loads configuration from self.confFile and sets values (self.$variable)
        """
        self.debug('Load Configuration')
        if os.path.exists(self.confFile):
            conf = None
            with open(self.confFile, 'r') as f:
                conf = json.load(f)
            #self.device = conf['device']
            #self.username = conf['username']
            #self.identFile = conf['identFile']
            #self.host = conf['host']
            #self.port = conf['port']
            #self.cache = conf['cache']
            #self.cacheUp = conf['cacheUp']
            #self.cacheDown = conf['cacheDown']
            #self.historyFile = conf['historyFile']
            #self.allocationFile = conf['allocationFile']
            #self.keyFile = conf['keyFile']
            #self.fingerprint = conf['fingerprint']
            #self.syncfolder = conf['syncfolder']
            #self.serverpath = conf['serverpath']
            #self.allocSync = conf['allocSync']
            #self.compression = conf['compression']
            #self.encryption = conf['encryption'].upper()
            rewrite = False
            keys = ['device', 'username', 'identFile', 'host', 'port', 'cache', 'cacheUp', 'cacheDown', 'historyFile', 'allocationFile', 'keyFile', 'fingerprint', 'syncfolder',
                    'serverpath', 'allocSync', 'compression', 'encryption']
            for key in keys:
                try:
                    exec('self.{} = conf[\'{}\']'.format(key, key))
                except KeyError as e:
                    self.debug('  KeyError: {}'.format(e))
                    rewrite = True
            if rewrite:
                self.storeConfiguration()
        else:
            self.storeConfiguration()


    def storeConfiguration(self):
        """
        Stores configuration into self.confFile (values read from self.$variable)
        """
        self.debug('Store Configuration')
        conf = {'device':self.device,
                'username':self.username,
                'identFile':self.identFile,
                'host':self.host,
                'port':self.port,
                'cache':self.cache,
                'cacheUp':self.cacheUp,
                'cacheDown':self.cacheDown,
                'historyFile':self.historyFile,
                'allocationFile':self.allocationFile,
                'keyFile':self.keyFile,
                'fingerprint':self.fingerprint,
                'syncfolder':self.syncfolder,
                'serverpath':self.serverpath,
                'allocSync':self.allocSync,
                'compression':self.compression,
                'encryption':self.encryption
               }
        with open(self.confFile, 'w') as f:
                json.dump(conf, f, sort_keys=True, indent=2)


    def loadMasterKey(self, genMasterKey=False):
        """
        Loads master key into self.masterKey, if genMasterKey is True and no key was found, key will be generated and storeMasterKey will be called

        @param genMasterKey: If True, master key is generated if not avaliable
        @type genMasterKey: bool
        @return: Returns master key
        """
        self.debug('Load master key')
        if os.path.exists(self.keyFile):
            data = None
            with open(self.keyFile, 'r') as f:
                data = f.read()
            self.masterKey = str(self.gpg.decrypt(data))
        else:
            if genMasterKey:
                self.masterKey = self.genSymKey()
                self.storeMasterKey()
            else:
                raise Exception('No master key found and i am not allowed to generate a new one')


    def storeMasterKey(self):
        """
        Stores master key (into self.keyFile)
        """
        self.debug('Store master key')
        gpgkey = self.getGpgKey()
        data = str(self.gpg.encrypt(self.masterKey, gpgkey['fingerprint']))
        with open(self.keyFile, 'w') as f:
            f.write(data)


    def getGpgKey(self):
        """
        Returns gpg key from self.gpg.list_keys() (key is found via self.fingerprint)

        @return: gpg key
        """
        self.debug('Get gpg key (from fingerprint {})'.format(self.fingerprint))
        gpgkey = None
        for key in self.gpg.list_keys():
            if key['fingerprint'].endswith(self.fingerprint):
                gpgkey = key
                break
        return gpgkey


    def loadClientAllocation(self):
        """
        Loads client allocation from self.allocationFile into self.allocation
        """
        self.debug('Load client allocation')
        if self.masterKey is None:
            raise Exception('Master key is None')
        data = None
        with open(self.allocationFile, 'r') as f:
            data = f.read()
        self.allocation = json.loads(str(self.gpg.decrypt(data, passphrase=self.masterKey)))


    def storeClientAllocation(self):
        """
        Stores client allocation (self.allocation) into self.allocationFile
        """
        self.debug('Store client allocation')
        if self.masterKey is None:
            raise Exception('Master key is None')
        data = str(self.gpg.encrypt(json.dumps(self.allocation), None, passphrase=self.masterKey, encrypt=False, symmetric=True, armor=True, cipher_algo=self.encryption))
        with open(self.allocationFile, 'w') as f:
            f.write(data)


    def getKey(self, hashsum):
        """
        Returns key from self.allocation

        @param hashsum: The hashsum to search for
        @type hashsum: str
        @return: Key for file with $hashsum
        """
        return self.allocation[hashsum][0]


    def setKey(self, hashsum, key):
        """
        Set (or update) key for $hashsum in self.allocation

        @param hashsum: The hashsum where the key needs to be set
        @type hashsum: str
        @param key: The key for $hashsum
        @type key: str
        """
        if hashsum in self.allocation:
            self.allocation[hashsum][0] = key
        else:
            self.allocation[hashsum] = [key, None]


    def getUri(self, hashsum, allocation=None):
        """
        Returns uri from self.allocation or, if allocation is not None, from allocation parameter

        @param hashsum: The hashsum to search for
        @type hashsum: str
        @return: Uri of file with $hashsum
        """
        if allocation is None:
            return self.allocation[hashsum][1]
        else:
            if hashsum in allocation:
                return allocation[hashsum]
            else:
                return self.allocation[hashsum][1]


    def setUri(self, hashsum, uri):
        """
        Set (or update) uri for $hashsum in self.allocation

        @param hashsum: The hashsum where the uri needs to be set
        @type hashsum: str
        @param uri: The uri for $hashsum
        @type uri: str
        """
        if hashsum in self.allocation:
            self.allocation[hashsum][1] = uri
        else:
            self.allocation[hashsum] = [None, uri]


    def getKeyUri(self, hashsum):
        """
        Returns [key, uri] from self.allocation

        @param hashsum: The hashsum to search for
        @type hashsum: str
        @return: [Key, Uri] for file with $hashsum
        """
        return self.allocation[hashsum]


    def setKeyUri(self, hashsum, key, uri):
        """
        Set (or update) key, uri for $hashsum in self.allocation

        @param hashsum: The hashsum
        @type hashsum: str
        @param key: The key for $hashsum
        @type key: str
        @param uri: The uri for $hashsum
        @type uri: str
        """
        self.allocation[hashsum] = [key, uri]


    def loadClientHistory(self):
        """
        Loads client history from self.historyFile and returns it

        @return: Returns history (as list)
        """
        self.debug('Load client history')
        if self.masterKey is None:
            raise Exception('Master key is None')
        data = None
        with open(self.historyFile, 'r') as f:
            data = f.read()
        history = json.loads(str(self.gpg.decrypt(data, passphrase=self.masterKey)))
        while '' in history:
            history.remove('')
        return history


    def storeClientHistory(self):
        """
        Stores client history from self.history
        """
        self.debug('Store client history')
        if self.masterKey is None:
            raise Exception('Master key is None')
        data = str(self.gpg.encrypt(json.dumps(self.history), None, passphrase=self.masterKey, encrypt=False, symmetric=True, armor=True, cipher_algo=self.encryption))
        with open(self.historyFile, 'w') as f:
            f.write(data)


    def getClientChanges(self):
        """
        Returns a list (history) of all changes between self.loadClientHistory() and the real changes made

        @return: Returns changes as history (list), dictionary with hashsum:uri
        """
        # Get the old files read from history
        oldHashsums = self.getHashsumsFromHistory(self.loadClientHistory())
        # Get the new files read from self.syncfolder's content
        newAllocation = {} # hashsum:uri
        newHashsums = []
        pathes = self.getFilesFromPath(self.syncfolder)
        for path in pathes:
            hashsum = self.getHash(path)
            newAllocation[hashsum] = path
            newHashsums.append(hashsum)
        # Get diff of hashsums
        historyDiff = self.getDiffFromHashsum(oldHashsums, newHashsums)
        # And return
        return historyDiff, newAllocation


    def getDiffFromHashsum(self, oldHashsums, newHashsums):
        """
        Returns a history-like diff of hashsums

        @param oldHashsums: List of hashsums, the „older“ version
        @type oldHashsums: list
        @param newHashsums: List of hashsums, the „newer“ or prior version
        @type newHashsums: list
        @return: History like diff of hashsums
        """
        history = []
        for hashsum in oldHashsums:
            if not hashsum in newHashsums:
                history.append('-{}'.format(hashsum))
        for hashsum in newHashsums:
            if not hashsum in oldHashsums:
                history.append('+{}'.format(hashsum))
        return history


    def getHashsumsFromHistory(self, history):
        """
        Returns a list of hashsums (extracted from history)

        @param history: history
        @type history: list
        @return: List of hashsums
        """
        hashsums = []
        for entry in history:
            if entry.startswith('+'):
                hashsums.append(entry[1:])
            elif entry.startswith('-'):
                hashsums.remove(entry[1:])
            elif entry.startswith('?'):
                hashsum1 = entry.split(' ')[0][1:]
                hashsum2 = entry.split(' ')[1]
                hashsums.remove(hashsum1)
                hashsums.append(hashsum2)
            else:
                raise Exception('Don\'t know what to do: {}'.format(entry))
        return hashsums


    #def getFilesFromHistory(self, history, allocation=None):
        #"""
        #Returns a list of files (extracted from history)
        #
        #@param history: History
        #@type history: list
        #@param allocation: Alternative dictionary containing the hashsum:uri allocation
        #@type allocation: dict
        #@return: List of files
        #"""
        #files = []
        #for entry in history:
            #if entry.startswith('+'):
                #uri = self.getUri(entry[1:], allocation)
                #files.append(uri)
            #elif hashsum.startswith('-'):
                #uri = self.getUri(entry[1:], allocation)
                #files.remove(uri)
            #elif hashsum.startswith('?'):
                #hashsum1 = entry.split(' ')[0][1:]
                #hashsum2 = entry.split(' ')[1]
                #uri1 = self.getUri(hashsum1, allocation)
                #uri2 = self.getUri(hashsum2, allocation)
                #files.remove(uri1)
                #files.append(uri2)
            #else:
                #raise Exception('Don\'t know what to do: {}'.format(entry))
        #return files


    def getFilesFromPath(self, path):
        """
        Returns a list of all files in path (including files in subdirectories)

        @param path: Absolute path to search for files
        @type path: str
        @return: List of files with relative pathes
        """
        #for root, dirs, files in os.walk(self.conf['syncfolder']):
        #    for item in files:
        #        path = item #os.path.join(root, item)
        #        hash = self.getHash(path)
        #        fileDict[path] = hash
        files = []
        if not os.path.islink(path):
            dirlist = os.listdir(path)
            for item in dirlist:
                if os.path.isdir(os.path.join(path, item)):
                    newpath = os.path.join(path, item)
                    files.extend(self.getFilesFromPath(newpath))
                else:
                    newpath = os.path.join(path, item)
                    files.append(newpath)
        return files


    def getHash(self, uri, hashtype='sha256'):
        """
        Generates hashsum of a file

        @param uri: path to the file (relative or absolute)
        @type uri: str
        @param hash: Type of hashsum, can be md5, sha1, sha224, sha256, sha384 or sha512
        @type hash: str
        @return: Returns hashsum of file including hashtype
        """
        # Make absolute path
        if not uri.startswith(self.syncfolder):
            while uri.startswith('/'):  # This is neccessary: > os.path.join('/one', '/two')
                uri = uri[1:]           #                     > '/two'
            uri = os.path.join(self.syncfolder, uri)
        # Get relative path
        uriRel = uri.replace(self.syncfolder, '', 1)
        while uriRel.startswith('/'):
            uriRel = uriRel[1:]
        # Generate hashsum of file
        hashsumFile = eval('hashlib.{}()'.format(hashtype.lower())) # executes for example „h = hashlib.sha256()“
        with open(uri, mode='rb') as f: # With updating the hashsum, the file size can be higher than the avaliable RAM
            while True:
                buf = f.read(4096)      # Maybe increase bufsize to get higher speed?!
                if not buf:
                    break
                hashsumFile.update(buf)
        hashsumAll = eval('hashlib.{}()'.format(hashtype.lower()))
        text = '{}{}'.format(uriRel, hashsumFile.hexdigest())
        hashsumAll.update(text.encode('utf-8'))
        self.debug('Generated Hashsum')
        self.debug('  Hashsum file: {}'.format(hashsumFile.hexdigest()))
        self.debug('  Hashsum all : {}'.format(hashsumAll.hexdigest()))
        self.debug('  Relpath     : {}'.format(uriRel))
        return '{}.{}'.format(hashsumAll.hexdigest(), hashtype.lower())


    def log(self, text):
        """
        Logging, should be overwritten

        @param text: Logtext
        @type text: str
        """
        self.debug('Log: {}'.format(text))


    def notify(self, text):
        """
        Notify, should be overwritten

        @param text: Notification text
        @type text: str
        """
        self.debug('Notifiy: {}'.format(text))


    def debug(self, text):
        """
        Prints debug text if self._debug is True

        @param text: Text to print
        @type text: str
        """
        if self._debug:
            print('Debug: {}'.format(text))


    def genSymKey(self, length=32):
        """
        Generates a nice symmetric key

        @param length: Length of symmetric key
        @type length: int
        @return: Returns a safe random key
        """
        # TODO: This is not fucking safe! (But still better than no key)
        chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(chars) for i in range(length))


    def connect(self):
        """
        Connects to server
        """
        self.debug('Connect to server')
        try:
            if self.transport.is_active():
                return    # Return if a transport is already opened. This could cause problems if, for example, the transport is open but the sftpclient is inactive/dead/etc
        except AttributeError:  # self.transport is not defined, so we should open it
            pass
        self.transport = paramiko.Transport((self.host, selfport))
        self.sftp = None
        if self.identityFile is None:
            self.debug('  Use password login')
            try:
                self.transport.connect(username=self.username, password=getpass.getpass('Serverpassword: '))
            except paramiko.ssh_exception.BadAuthenticationType:
                self.debug('Hm. Login with password doesn\'t work. Did you set „identityFile“ in {}?'.format(self.confFile))
                raise
        else:
            self.debug('  Use identity file login')
            key = None
            identFile = os.path.expanduser(self.identityFile)
            try:
                key = paramiko.RSAKey.from_private_key_file(identFile)
            except paramiko.ssh_exception.PasswordRequiredException:
                key = paramiko.RSAKey.from_private_key_file(identFile, password=getpass.getpass('Password for identity file: '))
            self.transport.connect(username=self.conf['username'], pkey=key)
        self.sftp = paramiko.SFTPClient.from_transport(self.transport)
        self.debug('Connect to server {}:{}'.format(self.host, self.port))


    def disconnect(self):
        """
        Disconnects from server

        """
        self.debug('Disconnecting from server')
        self.sftp.close()
        self.transport.close()


    def getLockName(self):
        """
        Get name of lock (who locked the server?)

        @return: Returns the name of the device which locked the server
        """
        self.sftp.chdir(self.serverpath)
        name = None
        with self.sftp.open('lock', 'r') as f:
            name = f.read()
            #name = name.decode(encoding='UTF-8')
            name = name.decode('utf-8') # convert bytes to string
            name = name.split('\n')[0]  # get first line
        return name


    def lock(self):
        """
        Try to lock server directory, raises exception if server can't be locked
        """
        self.debug('Lock server directory')
        self.sftp.chdir(self.serverpath)
        if 'lock' in self.sftp.listdir(self.serverpath):
            if self.name == self.getLockName():
                self.debug('  Already locked (from this device)')
            else:
                self.debug('  Already locked (from {})'.format(name))
                raise Exception('  Cannot lock server directory (locked by {})'.format(name))
        else:
            with self.sftp.open('lock', 'w') as f:
                f.write(self.conf['name'])


    def unlock(self, override=False):
        """
        Unlocks the server directory, if lock from another device and override is True, lock will also be removed
        """
        self.debug('Unlock server directory')
        self.sftp.chdir(self.serverpath)
        if 'lock' in self.sftp.listdir(self.serverpath):
            if self.name == self.getLockName():
                self.sftp.remove('lock')
                self.debug('  Removed lock')
            else:
                if override:
                    self.sftp.remove('lock')
                    self.debug('  Overriding lock - removing it')
                else:
                    raise Exception('  Could not unlock server directory')
        else:
            self.debug('  Server is not locked')


    def compress(self, fin):
        """
        Compress a file

        @param fin: File input path, can be relative within self.syncfolder or absolute (but still within self.syncfolder)
        @type fin: str
        @return: Absolute path to compressed file (within cacheUp)
        """
        self.debug('Compressing file: {}'.format(fin))
        hashsum = self.getHash(fin)
        # Select compression mode
        modes = {'lzma' : 'w:xz',
                 'bzip2': 'w:bz2',
                 'gzip' : 'w:gz',
                 None   : 'w'
                 }
        mode = modes[self.compression]
        if mode is None: # Fallback
            self.debug(' Using fallback, bz2-compression')
            mode = 'w:bz2'
        if not fin.startswith(self.syncfolder):
            while fin.startswith('/'):  # This is neccessary: > os.path.join('/one', '/two')
                fin = fin[1:]           #                     > '/two'
            fin = os.path.join(self.syncfolder, fin)
        fout = os.path.join(self.cacheUp, hashsum)
        with tarfile.open(fout, mode) as f:  # Use tarfile.open() instead of tarfile.TarFile() [look at the python docs for a reason]
            arcname = fin.replace(self.syncfolder, '', 1)
            f.add(fin, arcname)
        return fout


    def decompress(self, fin, delete=True):
        """
        Decompresses a file into self.syncfolder

        @param fin: File input path, must be within self.cacheDown, can either be relative or absolute
        @type fin: str
        @param delete: If True, after decompressing the file will be removed
        @type delete: bool
        """
        if not fin.startswith(self.cacheDown):
            fin = os.path.join(self.cacheDown, fin)
        with tarfile.open(fin, 'r') as f:   # We don't need to set a decompression algorithm. Not bad, isn't it?
            f.extractall(self.syncfolder)   # Direct extract into self.syncfolder
        if delete:
            os.remove(fin)


    def sync(self):
        """
        Synchronize with server (full-sync)
        """
        self.debug('Syncing, please wait...')
        # TODO: 3-way-merge: Client history < Server history < Real made local changes
        localHistory, localAllocation = self.getClientChanges()







        # Connect
        self.connect()

        # Get local changes, compress and encrypt

        # Get updates from server

        # Merge with local changes

        # Get updates from server

        # Send updates to the server

        # Disconnect
        self.disconnet()
        # Decrypt new files

        # Decompress new files

        # Done


########### cut #############


    #def sync(self):
        #"""
        #Synchronizes with the server (full-sync)
        #"""
        #self.debug('Sync')
        ## Load allocation
        #self.loadClientAllocation()
        ## Connect
        #self.connect()
        ## Pull latest updates from server
        #self.syncFromServer(disconnect=False) # Hold connection open, do not disconnect!
        ## Push latest updates to the server
        #self.syncToServer()
        ## Disconnect
        #self.disconnect() # we don't need to disconnect, syncToServer() does this for us
        ## Store allocation
        #self.storeClientAllocation()


    #def syncFromServer(self, disconnect=True):
        #"""
        #Pull the latest updates from server and merge with local folder

        #@param disconnect: If false, connection stays open
        #@type disconnect: bool
        #"""
        #self.debug('SyncFromServer')
        ## Connect
        #self.connect()
        ## Download server history and get local history
        #historyServer = self.getServerHistory()
        #historyClient = self.getClientHistory()
        ## Get diff to local version
        #historyDiff = self.getHistoryDiff(historyClient, historyServer)
        ## First we only download all new things, removing, extraction, etc is done later
        #for item in historyDiff:
            #if item.startswith('+'):
                #self.debug('Downloading... {}'.format(item[1:]))
                #remote = os.path.join(self.conf['serverpath'], 'files', item[1:])
                #local = os.path.join(self.conf['cacheDown'], item[1:])
                #localPart = '{}.part'.format(local)
                #self.sftp.get(remote, localPart)    # Download to a .part file
                #shutil.move(localPart, local)   # Move when download is finished
                #self.debug('  Done')
            #elif item.startswith('?'):
                #old, new = item.split(' ')
                #self.debug('Downloading... {}'.format(new))
                #remote = os.path.join(self.conf['serverpath'], 'files', new)
                #local = os.path.join(self.conf['cacheDown'], new)
                #localPart = '{}.part'.format(local)
                #self.sftp.get(remote, localPart)    # Download to a .part file
                #shutil.move(localPart, local)   # Move when download is finished
                #self.debug('  Done')
        ## Download alloc.conf if possible and write into local alloc.conf
        #if 'alloc.conf' in self.sftp.listdir(self.conf['serverpath']):
            #allocServer = None
            #with self.sftp.open(os.path.join(self.conf['serverpath'], 'alloc.conf'), 'r') as f:
                #data = f.read().decode('utf-8') # TODO: Do this right! As i heard, decode should not be used in cases like this. Maybe there are smarter ways
                #allocServer = json.loads(data)
            #allocClient = None
            #with open(self.conf['allocation'], 'r') as f:
                #allocClient = json.loads(f.read())
            #for key in allocServer:
                #if not key in allocClient:
                    #allocClient[key] = allocServer[key]
            #self.writeConf(self.conf['allocation'], allocClient)
        ## Disconnect
        #if disconnect:
            #self.disconnect()
        ## Apply changes, decrypt files, update history, decompress, etc
        #for item in historyDiff:
            #if item.startswith('-'):
                ## Get URI
                #uri = self.getURI(item[1:])
                #if uri is not None:
                    ## Remove
                    #os.remove(os.path.join(self.conf['syncfolder'], uri))
                    ## Add item to local history
                    #self.addHistory(item)
            #elif item.startswith('+'):
                ## Decrypt
                #path = os.path.join(self.conf['cacheDown'], item[1:])
                #self.decrypt(path, path, item[1:])
                ## Decompress and move
                #self.decompress(item[1:])
                ## Remove archive
                #os.remove(os.path.join(self.conf['cacheDown'], item[1:]))
                ## Add item to local history
                #self.addHistory(item)
            ##elif item.startswith('?'):
            ##    # Decrypt
            ##
            ##    # Decompress and overwrite
            ##    self.decompress)
            ##    # Remove archive
            ##    os.remove(os.path.join(self.conf['cacheDown'], ...)
            ##    # Add item to local history
            ##    self.addHistory(item)
            #else:
                #raise Exception('What. The. Fuck. {}'.format(item))


    #def syncToServer(self, disconnect=True):
        #"""
        #Push the latest updates to the server

        #@param disconnect: If false, connection stays open
        #@type disconnect: bool
        #"""
        #self.debug('SyncToServer')
        ## Get local history and the files still present (as history)
        #historyClient = self.getClientHistory()
        #historyChanges, uris = self.getClientChanges()
        ## Get diff to local history
        #historyDiff = self.getHistoryDiff(historyChanges, historyClient)
        #print(historyDiff)
        ## For every item in history diff
        #for item in historyDiff:
            ##if uri is not None:
            #if item.startswith('-'):
                ## Get uri
                #uri = self.getURI(item[1:])
                ## Remove file
                #os.remove(os.path.join(self.conf['syncfolder'], uri))
                ## Add item to local history
                #self.addHistory(item)
            #elif item.startswith('+'):
                ## Get uri
                #uri = uris[item[1:]]
                ## Compress file
                #self.compress(uri)
                ## Encrypt file
                #path = os.path.join(self.conf['cacheUp'], item[1:])
                #self.encrypt(path, path, item[1:])
                ## Update history
                #self.addHistory(item)
            #elif item.startswith('?'):
                ## This won't happen.
                #raise Exception('This should not happen, seems like your diff contains a new, experimental feature :)')
            #else:
                #raise Exception('What. The. Fuck. {}'.format(item))
            ##else:
            ##    raise Exception('What. The. Fuck. {}'.format(item))
        ## Connect
        #self.connect()
        ## Lock
        #self.lock()
        ## Update server history
        #history = self.getServerHistory()
        #for item in historyDiff:
            #history.append(item)
        ## Upload new server history
        #with self.sftp.open(os.path.join(self.conf['serverpath'], 'history.log'), 'w') as f:
            #for item in history:
                #f.write('{}\n'.format(item))
        ## Upload/(Re)move files
        #for item in historyDiff:
            #self.debug('Uploading... {}'.format(item[1:]))
            #local = os.path.join(self.conf['cacheUp'], item[1:])
            #remote = os.path.join(self.conf['serverpath'], 'files', item[1:])
            #self.sftp.put(local, remote)
            #os.remove(local)    # Remove source file
            #self.debug('  Done')
        ## Unlock
        #self.unlock()
        ## Disconnect
        #if disconnect:
            #self.disconnect()



    #def getServerHistory(self):
    #    """
    #    Pulls the server history and splits it into a list
    #
    #    @return: History of the server
    #    """
    #    data = None #''
    #    with self.sftp.open(os.path.join(self.conf['serverpath'], 'history.log'), 'r') as f:
    #        #data = str(f.read()) # Does not work as expected
    #        data = f.read().decode('utf-8') # TODO: Do this right! As i heard, decode should not be used in cases like this. Maybe there are smarter ways
    #    # Decrypt data
    #    raise Exception('Data needs to be decrypted!')
    #    history = data.split('\n')
    #    while '' in history:
    #        history.remove('')
    #    return history


    #def getClientChanges(self):
    #    """
    #    Returns a list with history and a dict(hash:uri)
    #
    #    @return: History of the local changes,dict(hash:uri)
    #    """
    #    history = []
    #    uris = {}
    #    #for root, dirs, files in os.walk(self.conf['syncfolder']):
    #    #   #    for item in files:
    #    #    #   path = item #os.path.join(root, item)
    #    #        hash = self.getHash(path)
    #    #        fileDict[path] = hash
    #    pathes = self.getFiles(self.conf['syncfolder'])
    #    for path in pathes:
    #        hashsum = self.getFilesFromPath(path)
    #        history.append('+{}'.format(hashsum))
    #        relPath = path.replace(self.conf['syncfolder'], '', 1)
    #        uris[hashsum] = relPath
    #    return history, uris


    #def getFilesFromPath(self, path):
    #    """
    #    Returns a list of all files in path (including files in subdirecotries)
    #
    #    @return: List of files
    #    """
    #    files = []
    #    if not os.path.islink(path):
    #        dirlist = os.listdir(path)
    #        for item in dirlist:
    #            if os.path.isdir(os.path.join(path, item)):
    #                newpath = os.path.join(path, item)
    #                files.extend(self.getFilesFromPath(newpath))
    #            else:
    #                newpath = os.path.join(path, item)
    #                files.append(newpath)
    #    return files


    #def getHistoryDiff(self, history1, history2):
    #    """
    #    Return the diff of two history-lists.
    #    There is no real prior history, but in the case of cases:
    #     - adding a file is prior to removing a file (well, should be)
    #     - history1 is prior to history2 (so, history1 is the „new“ history, history2 should be the „old“ history)
    #
    #    @param history1: First history (should be newer)
    #    @type history1: list
    #    @param history2: Second history (should be older)
    #    @type history2: list
    #    @return: A history of the differences
    #    """
    #    # TODO: Make a better, a true diff (because here we don't get a real diff)
    #    diff = []
    #    # Get a list of all files in (history1, history2)
    #    files1 = self.getFiles(history1)
    #    files2 = self.getFiles(history2)
    #    ## First remove, then add (makes sure at the end there are more files than with first add, the remove, believe me)
    #    ## If file is in 2 and not in 1:
    #    for item in files2:
    #        if not item in files1:
    #            diff.append('-{}'.format(item))
    #    # If file is in 1 and not in 2:
    #    for item in files1:
    #        if not item in files2:
    #            diff.append('+{}'.format(item))
    #    # Return
    #    return diff


    #def getFilesFromHistory(self, history, ignoreFaults=True):
    #    """
    #    Return a list of all files that should still be present (parses the history and returns all leftover files)
    #
    #    @param history: A history
    #    @type history: list
    #    @param ignoreFaults: If true, errors in history are ignored. If false, an exception is raised
    #    @type ignoreFaults: bool
    #    @return: list
    #    """
    #    files = []
    #    for item in history:
    #        item = str(item)
    #        if item.startswith('+'):
    #            if not item[1:] in files:
    #                files.append(item[1:])
    #        elif item.startswith('-'):
    #            files.remove(item[1:])
    #        elif item.startswith('?'):
    #            fileRemove = item.split(' ')[0][1:]
    #            fileAdd = item.split(' ')[1]
    #            files.remove(fileRemove)
    #            if not item[1:] in files:
    #                files.append(fileAdd)
    #        else:
    #            if not ignoreFaults:
    #                raise Exception('There\'s an error in your history:\n  „{}“'.format(item))
    #            self.debug('There\'s an error in your history. Good for you that errors ar ignored...\n  „{}“'.format(item))
    #    return files





    #def encrypt(self, fin, fout, hashsum, uri, delete=True):
        #"""
        #Encrypts a file

        #@param fin: Input file, absolute path
        #@type fin: str
        #@param fin: Output file, absolute path
        #@type fin: str
        #@param delete: Delete input file (only works if not fin==fout)
        #@type delete: bool
        #"""
        ## TODO: Rewrite this, everyone using px aux oder top can view the passphrase
        ##       Using the advanced python-gnupg mentioned in the Readme-section of this file!
        ##print('Hint: Encryption is not safe!')
        ##tmpfile = '{}.enc'.format(fout)
        ##pw = self.genSymKey()
        ### Encrypt file
        ##args = ['gpg', '--armor', '--symmetric', '--cipher-algo', 'aes256', '--output', tmpfile, '--batch', '--passphrase', pw, fin]
        ##p = subprocess.Popen(args)
        ### Store password
        ##alloc = None
        ##with open(self.conf['allocation'], 'r') as f:
        ##    alloc = json.loads(f.read())
        ##alloc[hashsum] = (pw, uri)
        ##with open(self.conf['allocation'], 'w') as f:
        ##    f.write(json.dumps(alloc))
        ### Move to destination
        ##shutil.move(tmpfile, fout)
        ### Remove fin if delete ist true and fin is not fout
        ##if delete and fin != fout:
        ##    os.remove(fin)
        ### Remove tmpfile
        ##os.remove(tmpfile)
        #pass


    #def decrypt(self, fin, fout, hashsum, delete=True):
        #"""
        #Decrypts a file

        #@param fin: Input file, absolute path
        #@type fin: str
        #@param fin: Output file, absolute path
        #@type fin: str
        #@param delete: Delete input file (only works if not fin==fout)
        #@type delete: bool
        #"""
        ## TODO: Rewrite this, everyone using px aux oder top can view the passphrase
        ##       Using the advanced python-gnupg mentioned in the Readme-section of this file!
        ##print('Hint: Decryption is not safe!')
        ##tmpfile = '{}.enc'.format(fout)
        ### Get password
        ##pw = self.getKey(hashsum)
        ### Encrypt file
        ##args = ['gpg', '--decrypt', '--output', tmpfile, '--batch', '--passphrase', pw, fin]
        ##p = subprocess.Popen(args)
        ### Move to destination
        ##shutil.move(tmpfile, fout)
        ### Remove fin if delete ist true and fin is not fout
        ##if delete and fin != fout:
        ##    os.remove(fin)
        #pass


    #def getKey(self, hashsum):
    #    """
    #    Returns the key of a hash (key is read from $allocation)
    #
    #    @param hashsum: The hashsum you need the key for
    #    @type hashsum: str
    #    @return: The key
    #    """
    #    raise Exception('getKey')
    #    #allocation = None
    #    #with open(self.conf['allocation'], 'r') as f:
    #    #    allocation = json.loads(f.read())
    #    #return allocation[hashsum][0]


    #def setKey(self, hashsum, key):
    #    """
    #    Add hash, key to $allocation
    #
    #    @param hashsum: The hash
    #    @type hashsum: str
    #    @param key: The key
    #    @type key: str
    #    """
    #    raise Exception('setKey')
    #    #allocation = None
    #    #with open(self.conf['allocation'], 'r') as f:
    #    #    allocation = json.loads(f.read())
    #    #allocation[hash] = key
    #    #with open(self.conf['allocation'], 'w') as f:
    #    #    f.write(json.dumps(allocation))
