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
#  `-- server.log
#
## Local structure
# $syncFolder
# $confFolder
#  .
#  |-- cache
#  |   |-- download
#  |   `-- upload
#  |-- cloudzec.conf
#  |-- client.log
#  `-- key
#
## client.log and server.log | JSON | optionally encrypted with masterkey | l6-format
#
# [
#   [modification_time, 'hash_all', 'path', 'hash_file', 'action', 'key'],
# ]
#
## The l6-format is a list in the following specification
#
# List index
# 0  - float  | Modification-time of the file in UNIX-format, from os.path.getmtime(path) or time.time()
# 1  - string | Hashsum of path and hashsum of file.  Example: h = hashlib.sha256('{}{}'.format(relative_path, hashsum_of_file))
# 2  - string | Relative path of file, e.g. folder/file1.txt
# 3  - string | Hashsum of file only
# 4  - string | Action, can either be +, - or ?. + means added, - means removed, ? means the file changed (like a word document with modificated content)
# 5  - string | The key for encryption. Maybe store external? Should only be synced if more than 1 device should have access
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
        self.clientLog = os.path.join(self.confFolder, 'client.log')    # Client.log in l6-format, JSON
        self.keyFile = os.path.join(self.confFolder, 'key')             # Key file with masterkey, not encrypted
        #self.fingerprint = fingerprint  # Fingerprint of gpg key
        self.syncFolder = os.path.join(home, 'CloudZec')    # Local sync-folder
        self.serverpath = serverpath    # Path on server
        self.masterKey = None           # Masterkey for alloc.conf en/decryption
        self.compression = None         # Preferred compression algorithm |lzma: slow compress, small file, very fast decompress |bzip2: fast compress, small file, fast decompress |gzip: big file, very fast compress, very fast decompress |Choose wisely
        self.encryption = 'AES256'      # Preferred encryption algorithm
        self.hashalgorithm = 'sha256'   # Preferred hash algorithm from hashlib:  md5, sha1, sha224, sha256, sha384, sha512
        # Create confFolder if missing
        if not os.path.exists(self.confFolder):
            self.debug('Create confFolder {}'.format(self.confFolder))
            os.makedirs(self.confFolder)
        # If confFile does not exists: Write the sample configuration-file and return
        if not os.path.exists(self.confFile):
            self.storeConfiguration()
            return
        else:
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
        conf = None
        with open(self.confFile, 'r') as f:
            conf = json.load(f)
        rewrite = False
        keys = ['username', 'identFile', 'host', 'port', 'cache', 'cacheUp', 'cacheDown', 'clientLog', 'keyFile', 'syncFolder', 'serverpath', 'compression', 'encryption']
        for key in keys:
            try:
                exec('self.{} = conf[\'{}\']'.format(key, key))
            except KeyError as e:
                self.debug('  KeyError: {}'.format(e))
                rewrite = True
        if rewrite:
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
                'clientLog':self.clientLog,
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
                raise Exception('No master key found and I am not allowed to generate a new one')


    def storeMasterKey(self):
        """
        Stores master key into self.keyFile
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


    def loadClientLog(self):
        """
        Loads client.log from self.clientLog and returns it

        @return: Returns list in l6-format
        """
        self.debug('Load client.log')
        client = []
        if os.path.exists(self.clientFile):
            data = None
            with open(self.clientLog, 'r') as f:
                data = f.read()
                client = json.loads(data)
        else:
            client = []
            self.storeClientFile(client)
        return client


    def storeClientLog(self, log):
        """
        Stores client into self.clientLog

        @param log: list in l6 format
        @type log: list
        """
        self.debug('Store client.log')
        with open(self.clientLog, 'w') as f:
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
        self.debug('Disconnect from server')
        self.sftp.close()
        self.transport.close()


    def getLockName(self):
        """
        Get name of lock (who locked the server?)

        @return: Returns the name of the device which locked the server
        """
        self.debug('Get lock name')
        self.sftp.chdir(self.serverpath)
        name = None
        with self.sftp.open('lock', 'r') as f:
            data = f.read()
            name = json.loads(data)
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
                json.dump(self.device, f)


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


    #def compress(self, fin):
    #    """
    #    Compress a file
    #
    #    @param fin: File input path, must be within self.syncFolder, can either be relative or absolute
    #    @type fin: str
    #    @return: Absolute path to compressed file (within cacheUp)
    #    """
    #    self.debug('Compressing file: {}'.format(fin))
    #    hashsum = self.getHash(fin)
    #    # Select compression mode
    #    modes = {'lzma' : 'w:xz',
    #             'bzip2': 'w:bz2',
    #             'gzip' : 'w:gz',
    #             None   : 'w'
    #             }
    #    mode = modes[self.compression]
    #    if mode is None: # Fallback
    #        self.debug(' Using fallback, no compression')
    #        mode = 'w'
    #    #if not fin.startswith(self.syncFolder):
    #    #    while fin.startswith('/'):  # This is neccessary: > os.path.join('/one', '/two')
    #    #        fin = fin[1:]           #                     > '/two'
    #    #    fin = os.path.join(self.syncFolder, fin)
    #    fin = os.path.join(self.syncFolder, fin)
    #    fout = os.path.join(self.cacheUp, hashsum)
    #    with tarfile.open(fout, mode) as f:  # Use tarfile.open() instead of tarfile.TarFile() [look at the python docs for a reason]
    #        arcname = fin.replace(self.syncFolder, '', 1)
    #        f.add(fin, arcname)
    #    return fout
    #
    #
    #def decompress(self, fin, delete=True):
    #    """
    #    Decompresses a file into self.syncFolder
    #
    #    @param fin: File input path, must be within self.cacheDown, can either be relative or absolute
    #    @type fin: str
    #    @param delete: If True, after decompressing the file will be removed
    #    @type delete: bool
    #    """
    #    if not fin.startswith(self.cacheDown):
    #        fin = os.path.join(self.cacheDown, fin)
    #    with tarfile.open(fin, 'r') as f:   # We don't need to set a decompression algorithm
    #        f.extractall(self.syncFolder)   # Direct extract into self.syncFolder
    #    if delete:
    #        os.remove(fin)


    def encrypt(self, fin, fout):
        """
        Encrypts fin and writes output to fout

        @param fin: File input path, must be absolute
        @type fin: str
        @param fout: File output path, must be absolute
        @ type fout: str
        """
        self.debug('Encrypt file')
        self.debug('  fin : {}'.format(fin))
        self.debug('  fout: {}'.format(fout))
        raise Exception('Not implemented')


    def decrypt(self, fin, fout):
        """
        Decrypts fin and writes output to fout

        @param fin: File input path, must be absolute
        @type fin: str
        @param fout: File output path, must be absolute
        @ type fout: str
        """
        self.debug('Decrypt file')
        self.debug('  fin : {}'.format(fin))
        self.debug('  fout: {}'.format(fout))
        raise Exception('Not implemented')


    def getHashOfFile(self, path_absolute):
        """
        Generates hashsum of a file and returns it

        @param path: path to the file (absolute)
        @type path: str
        @return: Returns hash_of_file, hash_all, both in .hexdigest()-format
        """
        self.debug('Get hash of file: {}'.format(path_absolute))
        # Get relative path
        path_relative = path_absolute.split(self.syncFolder)[1][1:]
        # Create hashsum of file
        exec('hash_file = hashlib.{}()'.format(self.hashalgorithm)) # Executes for example h = hashlib.sha256(), hash algorithm is set via self.hashalgorithm() in __init__()
        with open(path_absolute, mode='rb') as f:
            while True:
                buf = f.read(4096) # Maybe increase buf-size for higher speed?!
                if not buf:
                    break
                hash_file.update(buf)
        # Create hashsum of "path+hash_file"
        exec('hash_all = hashlib.{}()'.format(self.hashalgorithm))  # Executes for example h = hashlib.sha256(), hash algorithm is set via self.hashalgorithm() in __init__()
        text = '{}{}'.format(path_relative, hash_file.hexdigest())
        hash_all.update(text.encode('utf-8'))    
        return hash_file.hexdigest(), hash_all.hexdigest()


    def genDictFromL6(self, l6):
        """
        Generates a dictionary from an l6 formatted list

        @param l6: L6 style list
        @type l6: list
        @return: Returns a dictionary
        """
        self.debug('Generate dict from l6-format list')
        l6.sort() # Sort by timestamp
        d = dict()
        for item in l6:
            if item[4] == '+':
                timestamp = item[0]
                hash_all = item[1]
                relative_path = item[2]
                hash_file = item[3]
                key = item[5]
                d[relative_path] = {'timestamp':timestamp, 'hash_all':hash_all, 'hash_file':hash_file, 'key':key}
            elif item[4] == '-':
                relative_path = item[2]
                if relative_path in d:
                    del d[relative_path]
            else:
                print('Don\'t know how to handle this: {}'.format(item[4]))
        return d


    def getRealFiles(self, compare_l6=None):
        """
        Returns a l6 formatted list of all files that are really in self.syncFolder

        @param compare_l6: If None, every file needs to be hashed. With a comprehension list the timestamp is used and a hash is only generated if the timestamps don't match
        @type compare_l6: list
        @return: l6-formatted list of all files that are really in self.syncFolder
        """
        raise


    def sync(self):
        """
        Full sync between client and server
        """
        self.debug('Full sync')
        # 
        client_l6 = None # l6 format of client.log
        real_l6   = None # l6 format of the files that are really in self.syncFolder
        # If client.log exists
        if os.path.exists(self.clientLog):
            # Open client.log
            with open(self.clientLog, 'r') as f:
                client_l6 = json.load(f)
            # Load real files
            real_l6 = self.getRealFiles(client_l6)
            # Merge
            
            # Store

        # If client.log doesn't exist
        else:
            # Load real files

            # Store

           

        #if not os.path.exists(self.clientLog):
        #    with open(self.clientLog, 'w') as f:
        #        json.dump(real_l6, f, indent=2)
        #else:
        #    with open(path_logfile, 'r') as f:
        #        log_state_list = json.load(f)



        # Merge client and real files
        
        # Store

        # Connect

        # Lock

        # If locked:

            # Load server list
            server_l6 = None # l6 format of server.log
    
            # Merge server and client
    
            # Create diff between client and server
    
            # Download/Upload files
    
            # Upload new server.log
    
            # Unlock

        # Disconnect

        # Done



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
