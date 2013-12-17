#!/usr/bin/env python3
# -*- coding: utf-8 -*-


## Readme | http://cloudzec.org
#
# This is the basic CloudZec Class
#
# Note to myself: First compress, then encrypt
#               : First remove, then add
#               : Hash is generated with „path+hashofFile“: „sha256('folder/file.txtdf870a68df70a86df076adf45a60d4f6a5')“, this makes sure every file includings its (relative) uri is really unique
#                                                           „sha256('file.txtdf870a68df70a86df076adf45a60d4f6a5')“
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
## GnuPG | pygpgme | There's a lack of documentation so i won't use it
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
#   --no-tty         Make sure that the TTY is never used for any output)
#   fin              The input file
# decryption:
#  gpg
#   --decrypt        Decrypt file
#   --output         Write output to a file
#    fout             The file
#   --batch          Batch mode, don't ask for anything, do not allow interactive commands, needed f$
#   --passphrase     Use string as the passphrase
#     pw              The passphrase
#   --no-tty         Make sure that the TTY is never used for any output)
#   fin              The input file
#
## Server structure
# $serverpath
#  .
#  |-- files
#  |-- lock
#  `-- server
#
## Local structure
# $syncFolder
# $confFolder
#  .
#  |-- cache
#  |   |-- download
#  |   `-- upload
#  |-- cloudzec.conf
#  |-- client
#  `-- key
#
## client | JSON | encrypted with masterkey | hist3 format
#
# [
#   [time.time(), '+hash1', 'folder/file1', 'key1'],
#   [time.time(), '+hash2', 'folder/file2', 'key2'],
#   [time.time(), '+hash3', 'folder/file3', 'key3'],
#   [time.time(), '+hash4', 'folder/file4', 'key4'],
#   [time.time(), '-hash2', 'folder/file2', 'key2'],
#   [time.time(), '+hash5', 'folder/file5', 'key5'],
#   [time.time(), '-hash3', 'folder/file3', 'key3']
# ]
#


## Imports
import getpass
import hashlib
import json
import os
import platform
import random
import string
import tarfile
import time
# External
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
        self.device = platform.node()        # Device name, neccessary for lock-name on server
        self.username = username    # Username for server-login
        self.identFile = identFile  # Identify file for server-login, None if passwordlogin is preferred over publickey
        self.host = host            # Server host
        self.port = port            # Server port
        self.cache = os.path.join(self.confFolder, 'cache')
        self.cacheUp = os.path.join(self.confFolder, 'cache', 'upload')
        self.cacheDown = os.path.join(self.confFolder, 'cache', 'download')
        self.clientFile = os.path.join(self.confFolder, 'client')   # Client file, JSON format, [[time.time(), '+hash1', 'key1', 'folder/file1'], ]
        self.keyFile = os.path.join(self.confFolder, 'key')         # Key file with masterkey, not encrypted
        #self.fingerprint = fingerprint  # Fingerprint of gpg key
        self.syncFolder = os.path.join(home, 'CloudZec')    # Local sync-folder
        self.serverpath = serverpath    # Path on server
        self.masterKey = None           # Masterkey for alloc.conf en/decryption
        self.compression = None         # Preferred compression algorithm |lzma: slow compress, small file, very fast decompress |bzip2: fast compress, small file, fast decompress |gzip: big file, very fast compress, very fast decompress |Choose wisely
        self.encryption = 'AES256'      # Preferred encryption algorithm
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
        # Check folder: syncFolder
        if not os.path.exists(self.syncFolder):
            self.debug('Create folder: {}'.format(self.syncFolder))
            os.makedirs(self.syncFolder)
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
        # Rewrite?
        if rewrite:
            self.debug('Rewrite configuration')
            self.storeConfiguration()


    def debug(self, text):
        """
        Prints debug text if self._debug is True

        @param text: Text to print
        @type text: str
        """
        if self._debug:
            print('Debug: {}'.format(text))


    def loadConfiguration(self):
        """
        Loads configuration from self.confFile and sets values (self.$variable)
        """
        self.debug('Load Configuration')
        if os.path.exists(self.confFile):
            conf = None
            with open(self.confFile, 'r') as f:
                conf = json.load(f)
            rewrite = False
            keys = ['username', 'identFile', 'host', 'port', 'cache', 'cacheUp', 'cacheDown', 'clientFile', 'keyFile', 'syncFolder', 'serverpath', 'compression', 'encryption']
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
        conf = {'username':self.username,
                'identFile':self.identFile,
                'host':self.host,
                'port':self.port,
                'cache':self.cache,
                'cacheUp':self.cacheUp,
                'cacheDown':self.cacheDown,
                'clientFile':self.clientFile,
                'keyFile':self.keyFile,
                'syncFolder':self.syncFolder,
                'serverpath':self.serverpath,
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
            #self.masterKey = str(self.gpg.decrypt(data))
            self.masterKey = json.loads(data)
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
        #gpgkey = self.getGpgKey()
        #data = str(self.gpg.encrypt(self.masterKey, gpgkey['fingerprint']))
        with open(self.keyFile, 'w') as f:
            #f.write(data)
            json.dump(self.masterKey, f)


    def genSymKey(self, length=32):
        """
        Generates a nice symmetric key

        @param length: Length of symmetric key
        @type length: int
        @return: Returns a safe random key
        """
        self.debug('Generate symmectric key')
        self.debug('  At the moment this is not a safe nor a really random key!')
        # TODO: This is not fucking safe! (But still better than no key)
        chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(chars) for i in range(length))


    def loadClientFile(self):
        """
        Loads hist3 from self.clientFile and returns it

        @return: Returns client hist3 list
        """
        client = []
        self.debug('Load client hist3 file')
        if os.path.exists(self.clientFile):
            data = None
            with open(self.clientFile, 'r') as f:
                data = f.read()
                client = json.loads(data)
        else:
            client = []
            self.storeClientFile(client)
        return client


    def storeClientFile(self, client):
        """
        Stores client into self.clientFile

        @param client: hist3 variable
        @type client: list
        """
        self.debug('Store client hist3 file')
        with open(self.clientFile, 'w') as f:
            json.dump(client, f, indent=2)


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
        self.transport = paramiko.Transport((self.host, self.port))
        self.sftp = None
        if self.identFile is None:
            self.debug('  Use password login')
            try:
                self.transport.connect(username=self.username, password=getpass.getpass('Serverpassword: '))
            except paramiko.ssh_exception.BadAuthenticationType:
                self.debug('Hm. Login with password doesn\'t work. Did you set „identFile“ in {}?'.format(self.confFile))
                raise
        else:
            self.debug('  Use identity file login')
            key = None
            identFile = os.path.expanduser(self.identFile)
            try:
                key = paramiko.RSAKey.from_private_key_file(identFile)
            except paramiko.ssh_exception.PasswordRequiredException:
                key = paramiko.RSAKey.from_private_key_file(identFile, password=getpass.getpass('Password for identity file: '))
            self.transport.connect(username=self.username, pkey=key)
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
            if self.device == self.getLockName():
                self.debug('  Already locked (from this device)')
            else:
                self.debug('  Already locked (from {})'.format(name))
                raise Exception('  Cannot lock server directory (locked by {})'.format(name))
        else:
            with self.sftp.open('lock', 'w') as f:
                f.write(self.device)


    def unlock(self, override=False):
        """
        Unlocks the server directory, if locked from another device and override is True, lock will also be removed
        """
        self.debug('Unlock server directory')
        self.sftp.chdir(self.serverpath)
        if 'lock' in self.sftp.listdir(self.serverpath):
            if self.device == self.getLockName():
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

        @param fin: File input path, must be within self.syncFolder, can either be relative or absolute
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
            self.debug(' Using fallback, no compression')
            mode = 'w'
        #if not fin.startswith(self.syncFolder):
        #    while fin.startswith('/'):  # This is neccessary: > os.path.join('/one', '/two')
        #        fin = fin[1:]           #                     > '/two'
        #    fin = os.path.join(self.syncFolder, fin)
        fin = os.path.join(self.syncFolder, fin)
        fout = os.path.join(self.cacheUp, hashsum)
        with tarfile.open(fout, mode) as f:  # Use tarfile.open() instead of tarfile.TarFile() [look at the python docs for a reason]
            arcname = fin.replace(self.syncFolder, '', 1)
            f.add(fin, arcname)
        return fout


    def decompress(self, fin, delete=True):
        """
        Decompresses a file into self.syncFolder

        @param fin: File input path, must be within self.cacheDown, can either be relative or absolute
        @type fin: str
        @param delete: If True, after decompressing the file will be removed
        @type delete: bool
        """
        if not fin.startswith(self.cacheDown):
            fin = os.path.join(self.cacheDown, fin)
        with tarfile.open(fin, 'r') as f:   # We don't need to set a decompression algorithm
            f.extractall(self.syncFolder)   # Direct extract into self.syncFolder
        if delete:
            os.remove(fin)


    def encrypt(self, fin, fout):
        """
        Encrypts fin and writes output to fout

        @param fin: File input path, must be absolute
        @type fin: str
        @param fout: File output path, must be absolute
        @ type fout: str
        """
        raise Exception('Not implemented')


    def decrypt(self, fin, fout):
        """
        Decrypts fin and writes output to fout

        @param fin: File input path, must be absolute
        @type fin: str
        @param fout: File output path, must be absolute
        @ type fout: str
        """
        raise Exception('Not implemented')


    def getHash(self, uri): #, hashtype='sha256'):
        """
        Generates hashsum of a file

        @param uri: path to the file (relative or absolute)
        @type uri: str
        @return: Returns hashsum of file in .hexdigest() format
        """
        #@param hash: Type of hashsum, can be md5, sha1, sha224, sha256, sha384 or sha512
        #@type hash: str
        #@return: Returns hashsum of file including hashtype
        #"""
        hashtype = 'sha256'
        # Make absolute path
        if not uri.startswith(self.syncFolder):
            while uri.startswith('/'):  # This is neccessary: > os.path.join('/one', '/two')
                uri = uri[1:]           #                     > '/two'
            uri = os.path.join(self.syncFolder, uri)
        # Get relative path
        uriRel = uri.replace(self.syncFolder, '', 1)
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
        #self.debug('Generated Hashsum')
        #self.debug('  Hashsum file: {}'.format(hashsumFile.hexdigest()))
        #self.debug('  Hashsum all : {}'.format(hashsumAll.hexdigest()))
        #self.debug('  Relpath     : {}'.format(uriRel))
        return hashsumAll.hexdigest()


    def sync(self):
        """
        Full sync between client and server
        """
        self.debug('Full sync')
        # Load hist3 from file, load real hist3, merge and save
        hist_file = self.loadClientFile()
        hist_real = self.getLocalFiles()
        hist_new = self.mergeHist3Lists(hist_file, hist_real)
        self.storeClientFile(hist_new)





        # Load server history
        #server_hist = None

        # Connect

        # Lock

        # Load server changes

        # 3 way merge (local changes have prio)

        # Apply changes:
            # For change in changes...

        # Synchronize client-server file

        # Cleanup on server?

        # Unlock

        # Disconnect

        # Done


    def mergeHist3Lists(self, hist3_1, hist3_2):
        """
        Merges 2 hist3 lists

        @return: Returns new, merged hist3 file
        """
        # Merge
        hist3_unified = hist3_1
        hist3_unified.extend(hist3_2)
        # Sort by time
        # time is the first value of each list, so we don't need an extra sort function like the following
        # sort_by_index = sorted(hist3_unified, key=lambda x: x[1])
        hist3_unified.sort()
        # Cleanup
        hist3_new = []



        # Done

        raise



    def getHashFromHist3(self, hist3):
        """
        Returns only the hashvalues from a hist3 list

        @return: list of hashsums
        """
        hashsums = []
        for item in hist3:
            hashsum = item[1]
            if hashsum.startswith('+'):
                hashsums.append(hashsum[1:])
            elif hashsum.startswith('-'):
                if hashsum[1:] in hashsums:
                    hashsums.remove(hashsum[1:])
                else:
                    self.debug('Tried to remove an invalid hashsum: {}'.format(hashsum))
            else:
                self.debug('I have no idea what to do with this: {}'.format(hashsum))
        return hashsums


    def getLocalFiles(self):
        """
        Returns a list of all files in self.syncFolder

        @return: List of files with relative pathes
        """
        # Get all files
        files = []
        for root, dirnames, filenames in os.walk(self.syncFolder):
            for filename in filenames:
                files.append(os.path.join(root, filename))
        # Create history like things [time.time(), '+hash', 'folder/file', 'key']
        hist = []
        for item in files:
            hash = self.getHash(item)
            relativePath = item.split(self.syncFolder)[1][1:]
            hist.append([time.time(), '+{}'.format(hash), relativePath, None])
            self.debug(hist[-1])
        # Return that thing
        return hist


    #def getGpgKey(self):
    #    """
    #    Returns gpg key from self.gpg.list_keys() (key is found via self.fingerprint)
    #
    #    @return: gpg key
    #    """
    #    self.debug('Get gpg key (from fingerprint {})'.format(self.fingerprint))
    #    gpgkey = None
    #    for key in self.gpg.list_keys():
    #        if key['fingerprint'].endswith(self.fingerprint):
    #            gpgkey = key
    #            break
    #    return gpgkey


    #def getKey(self, hashsum):
    #    """
    #    Returns key from self.allocation
    #
    #    @param hashsum: The hashsum to search for
    #    @type hashsum: str
    #    @return: Key for file with $hashsum
    #    """
    #    return self.allocation[hashsum][0]


    #def setKey(self, hashsum, key):
    #    """
    #    Set (or update) key for $hashsum in self.allocation
    #
    #    @param hashsum: The hashsum where the key needs to be set
    #    @type hashsum: str
    #    @param key: The key for $hashsum
    #    @type key: str
    #    """
    #    if hashsum in self.allocation:
    #        self.allocation[hashsum][0] = key
    #    else:
    #        self.allocation[hashsum] = [key, None]


    #def getUri(self, hashsum, allocation=None):
    #    """
    #    Returns uri from self.allocation or, if allocation is not None, from allocation parameter
    #
    #    @param hashsum: The hashsum to search for
    #    @type hashsum: str
    #    @return: Uri of file with $hashsum
    #    """
    #    if allocation is None:
    #        return self.allocation[hashsum][1]
    #    else:
    #        if hashsum in allocation:
    #            return allocation[hashsum]
    #        else:
    #            return self.allocation[hashsum][1]


    #def setUri(self, hashsum, uri):
    #    """
    #    Set (or update) uri for $hashsum in self.allocation
    #
    #    @param hashsum: The hashsum where the uri needs to be set
    #    @type hashsum: str
    #    @param uri: The uri for $hashsum
    #    @type uri: str
    #    """
    #    if hashsum in self.allocation:
    #        self.allocation[hashsum][1] = uri
    #    else:
    #        self.allocation[hashsum] = [None, uri]


    #def getKeyUri(self, hashsum):
    #    """
    #    Returns [key, uri] from self.allocation
    #
    #    @param hashsum: The hashsum to search for
    #    @type hashsum: str
    #    @return: [Key, Uri] for file with $hashsum
    #    """
    #    return self.allocation[hashsum]


    #def setKeyUri(self, hashsum, key, uri):
    #    """
    #    Set (or update) key, uri for $hashsum in self.allocation
    #
    #    @param hashsum: The hashsum
    #    @type hashsum: str
    #    @param key: The key for $hashsum
    #    @type key: str
    #    @param uri: The uri for $hashsum
    #    @type uri: str
    #    """
    #    self.allocation[hashsum] = [key, uri]


    #def loadClientHistory(self):
    #    """
    #    Loads client history from self.historyFile and returns it
    #
    #    @return: Returns history (as list)
    #    """
    #    self.debug('Load client history')
    #    if self.masterKey is None:
    #        raise Exception('Master key is None')
    #    data = None
    #    with open(self.historyFile, 'r') as f:
    #        data = f.read()
    #    history = json.loads(str(self.gpg.decrypt(data, passphrase=self.masterKey)))
    #    while '' in history:
    #        history.remove('')
    #    return history
    #
    #
    #def storeClientHistory(self):
    #    """
    #    Stores client history from self.history
    #    """
    #    self.debug('Store client history')
    #    if self.masterKey is None:
    #        raise Exception('Master key is None')
    #    data = str(self.gpg.encrypt(json.dumps(self.history), None, passphrase=self.masterKey, encrypt=False, symmetric=True, armor=True, cipher_algo=self.encryption))
    #    with open(self.historyFile, 'w') as f:
    #        f.write(data)


    #def getClientChanges(self):
    #    """
    #    Returns a list (history) of all changes between self.loadClientHistory() and the real changes made
    #
    #    @return: Returns changes as history (list), dictionary with hashsum:uri
    #    """
    #    # Get the old files read from history
    #    oldHashsums = self.getHashsumsFromHistory(self.loadClientHistory())
    #    # Get the new files read from self.syncFolder's content
    #    newAllocation = {} # hashsum:uri
    #    newHashsums = []
    #    pathes = self.getFilesFromPath(self.syncFolder)
    #    for path in pathes:
    #        hashsum = self.getHash(path)
    #        newAllocation[hashsum] = path
    #        newHashsums.append(hashsum)
    #    # Get diff of hashsums
    #    historyDiff = self.getDiffFromHashsum(oldHashsums, newHashsums)
    #    # And return
    #    return historyDiff, newAllocation


    #def getClientChanges2(self):
    #    """
    #    Returns a list (history) of all changes between self.loadClientHistory2() and the real made changes
    #
    #    @return: Returns changes as history (list), dictionary with hashsum:uri
    #    """
    #    # Get the old files read from history
    #    oladHashsums = self.getHashsumsFromHistory2(self.loadClientHistory2())
    #    # Get the new files read from self.syncFolders content
    #    newAllocation = {} # hashsum:uri
    #    newHashsums = []
    #    pathes = self.getFilesFromPath(self.syncFolder)
    #    for path in pathes:
    #        hashsum = self.getHash(path)
    #        newAllocation[hashsum] = path
    #        newHashsums.append(hashsum)
    #    # Get diff of hashsums
    #    historyDiff = self.getDiffFromHashsum(oldHashsums, newHashsums)
    #    # And return
    #    return historyDiff, newAllocation


    #def getDiffFromHashsum(self, oldHashsums, newHashsums):
    #    """
    #    Returns a history-like diff of hashsums
    #
    #    @param oldHashsums: List of hashsums, the „older“ version
    #    @type oldHashsums: list
    #    @param newHashsums: List of hashsums, the „newer“ or prior version
    #    @type newHashsums: list
    #    @return: History like diff of hashsums
    #    """
    #    history = []
    #    for hashsum in oldHashsums:
    #        if not hashsum in newHashsums:
    #            history.append('-{}'.format(hashsum))
    #    for hashsum in newHashsums:
    #        if not hashsum in oldHashsums:
    #            history.append('+{}'.format(hashsum))
    #    return history


    #def getHashsumsFromHistory(self, history):
    #    """
    #    Returns a list of hashsums (extracted from history)
    #
    #    @param history: history
    #    @type history: list
    #    @return: List of hashsums
    #    """
    #    hashsums = []
    #    for entry in history:
    #        if entry.startswith('+'):
    #            hashsums.append(entry[1:])
    #        elif entry.startswith('-'):
    #            hashsums.remove(entry[1:])
    #        elif entry.startswith('?'):
    #            hashsum1 = entry.split(' ')[0][1:]
    #            hashsum2 = entry.split(' ')[1]
    #            hashsums.remove(hashsum1)
    #            hashsums.append(hashsum2)
    #        else:
    #            raise Exception('Don\'t know what to do: {}'.format(entry))
    #    return hashsums


    #def getHashsumsFromHistory2(self, history):
    #    """
    #    Returns a list of hashsums (extracted from history)
    #
    #    @param history: history
    #    @type history: list
    #    @return: List of hashsums
    #    """
    #    hashsums = []
    #    for entry in history:
    #        if entry[1].startswith('+'):
    #            hashsums.append(entry[1:])
    #        elif entry[1].startswith('-'):
    #            hashsums.remove(entry[1:])
    #        #elif entry[1].startswith('?'):
    #        #    hashsum1 = entry[1].split(' ')[0][1:]
    #        #    hashsum2 = entry[1].split(' ')[1]
    #        #    hashsums.remove(hashsum1)
    #        #    hashsums.append(hashsum2)
    #        else:
    #            raise Exception('Don\'t know what to do: {}'.format(entry))
    #    return hashsums


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


    #def getFilesFromPath(self, path):
    #    """
    #    Returns a list of all files in path (including files in subdirectories)
    #
    #    @param path: Absolute path to search for files
    #    @type path: str
    #    @return: List of files with relative pathes
    #    """
    #    #for root, dirs, files in os.walk(self.conf['syncFolder']):
    #    #    for item in files:
    #    #        path = item #os.path.join(root, item)
    #    #        hash = self.getHash(path)
    #    #        fileDict[path] = hash
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
