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
#
## Compression | TarFile | Maybe no compression because compression could be too slow for large files with no benefit
#  http://docs.python.org/3.3/library/tarfile.html
#  http://docs.python.org/3.3/library/archiving.html
#
#
## GnuPG | python-gnupg fork | Fast development, including security patches, etc.
#  https://github.com/isislovecruft/python-gnupg/
#  https://python-gnupg.readthedocs.org/en/latest/gnupg.html#gnupg-module
#
#
## GnuPG | python-gnupg | very slow development, security patches?
#  http://code.google.com/p/python-gnupg/
#  http://pythonhosted.org/python-gnupg/
#
#
## GnuPG | pygpgme | There's a lack of documentation so i won't use it
#  https://aur.archlinux.org/packages/pygpgme/
#  https://code.launchpad.net/~jamesh/pygpgme/trunk
#  http://pastebin.com/F1BY5vVR
#
#
## Paramiko | python-paramiko
#  https://github.com/paramiko/paramiko
#  https://github.com/paramiko/paramiko/issues/16
#  https://github.com/nischu7/paramiko
#  https://github.com/revogit/paramiko
#
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
#
## Server structure
# $serverpath
#  .
#  |-- files
#  |-- lock
#  `-- server.log
#
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
#  |-- keys
#  `-- masterkey
#
#
## client.log and server.log | JSON | optionally encrypted with masterkey | l5-format
#
# [
#   [timestamp, 'hash_all', 'path', 'hash_file', 'action'],
# ]
#
## The l5-format is a list in the following specification
#
# List index
# 0  - float  | Modification-time of the file in UNIX-format, from os.path.getmtime(path) or time.time()
# 1  - string | Hashsum of path and hashsum of file.  Example: h = hashlib.sha256('{}{}'.format(relative_path, hashsum_of_file)) NOT IN USE AT THE MOMENT: value is always NONE! [Will be dropped later]
# 2  - string | Relative path of file, e.g. folder/file1.txt
# 3  - string | Hashsum of file only
# 4  - string | Action, can either be +, - or ?. + means added, - means removed, ? means the file changed (like a word document with modified content), ? is not implemented at the moment!
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
import errno
# External
import gnupg
import paramiko


## Classes
class CloudZec:
    def __init__(self, username=None, identFile=None, host='cloudzec.org', port=22, fingerprint=None, serverPath=None, allocSync=True, genMasterKey=True, debug=False):
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
        self.clientLog = os.path.join(self.confFolder, 'client.log')
        self.keyFile  = os.path.join(self.confFolder, 'key')             # Key file with masterkey, not encrypted
        self.keysFile = os.path.join(self.confFolder, 'keys')            # Keys file with keys, should be encrypted
        #self.fingerprint = fingerprint  # Fingerprint of gpg key
        self.syncFolder = os.path.join(home, 'CloudZec')    # Local sync-folder
        self.serverPath = serverPath    # Path on server
        self.masterKey = None           # Masterkey for client.log/server.log and keys-file en/decryption
        self.keys      = {}             # Keys for data en/decryption
        self.compression = None         # Preferred compression algorithm |lzma: slow compress, small file, very fast decompress |bzip2: fast compress, small file, fast decompress |gzip: big file, very fast compress, very fast decompress |Choose wisely
        self.encryption = 'AES256'      # Preferred encryption algorithm
        self.hashalgorithm = 'sha256'   # Preferred hash algorithm from hashlib:  md5, sha1, sha224, sha256, sha384, sha512
        self.useTimestamp = True        # If true, a timestamp comparison is done instead of generating hashsums. This speed ups a lot but is not as good as comparing hashsums
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
        # Check serverPath | path like /home/$username/cloudzec on the server!
        if self.serverPath is None:
            self.debug('Create default serverPath')
            self.serverPath = os.path.join('/home', self.username, 'cloudzec')
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
        ## Load keys
        self.loadKeys()
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
        keys = ['username', 'identFile', 'host', 'port', 'cache', 'cacheUp', 'cacheDown', 'clientLog', 'keyFile', 'syncFolder', 'serverPath', 'compression', 'encryption', 'useTimestamp']
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
        keys = ['username', 'identFile', 'host', 'port', 'cache', 'cacheUp', 'cacheDown', 'clientLog', 'keyFile', 'syncFolder', 'serverPath', 'compression', 'encryption', 'useTimestamp']
        conf = {}
        for key in keys:
            exec('conf[\'{}\'] = self.{}'.format(key, key))
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


    def loadKeys(self):
        """
        Load keys into self.keys
        """
        self.debug('Load keys')
        if os.path.exists(self.keysFile):
            data = None
            with open(self.keysFile, 'r') as f:
                data = f.read()
            #self.masterKey = str(self.gpg.decrypt(data))
            self.keys = json.loads(data)


    def storeKeys(self):
        """
        Store keys into self.keysFile
        """
        self.debug('Store keys')
        #gpgkey = self.getGpgKey()
        #data = str(self.gpg.encrypt(self.masterKey, gpgkey['fingerprint']))
        with open(self.keysFile, 'w') as f:
            #f.write(data)
            json.dump(self.keys, f)


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

        @return: Returns list in l5-format
        """
        self.debug('Load client.log')
        client = []
        if os.path.exists(self.clientLog):
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

        @param log: list in l5 format
        @type log: list
        """
        self.debug('Store client.log')
        with open(self.clientLog, 'w') as f:
            json.dump(log, f, indent=2)


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
        self.debug('Connected to server {}@{}:{}'.format(self.username, self.host, self.port))


    def disconnect(self):
        """
        Disconnect from server
        """
        self.debug('Disconnect from server')
        self.sftp.close()
        self.transport.close()
        self.debug('Disconnected from server')


    def getLockName(self):
        """
        Get name of lock (who locked the server?)

        @return: Returns the name of the device which locked the server
        """
        self.debug('Get lock name')
        self.sftp.chdir(self.serverPath)
        name = None
        with self.sftp.open('lock', 'r') as f:
            data = f.read()
            name = json.loads(data) #data.decode('utf-8')) # TODO: Ugly bin-str decode
        return name


    def lock(self):
        """
        Try to lock server directory, raises exception if server can't be locked
        """
        self.debug('Lock server directory')
        self.sftp.chdir(self.serverPath)
        if 'lock' in self.sftp.listdir(self.serverPath):
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
        self.sftp.chdir(self.serverPath)
        if 'lock' in self.sftp.listdir(self.serverPath):
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


    def getHashOfFile(self, path_absolute):
        """
        Generates hashsum of a file and returns it

        @param path: path to the file (absolute)
        @type path: str
        @return: Returns hash_file in .hexdigest()-format
        """
        self.debug('Get hash of file: {}'.format(path_absolute))
        ## Get relative path
        #path_relative = path_absolute.split(self.syncFolder)[1][1:]
        # Create hashsum of file
        hash_file = hashlib.sha256()
        self.debug('TODO: Rewrite getHashOfFile() to support more than sha256!')
        #exec('hash_file = hashlib.{}()'.format(self.hashalgorithm)) # Executes for example h = hashlib.sha256(), hash algorithm is set via self.hashalgorithm() in __init__()
        with open(path_absolute, mode='rb') as f:
            while True:
                buf = f.read(4096) # Maybe increase buf-size for higher speed?!
                if not buf:
                    break
                hash_file.update(buf)
        # Create hashsum of "path+hash_file"
        #exec('hash_all = hashlib.{}()'.format(self.hashalgorithm))  # Executes for example h = hashlib.sha256(), hash algorithm is set via self.hashalgorithm() in __init__()
        #text = '{}{}'.format(path_relative, hash_file.hexdigest())
        #hash_all.update(text.encode('utf-8'))    
        return hash_file.hexdigest() #, hash_all.hexdigest()


    def genDictFromL5(self, l5):
        """
        Generates a dictionary from an l5 formatted list

        @param l5: L5 style list
        @type l5: list
        @return: Returns a dictionary
        """
        self.debug('Generate dict from l5-format list')
        l5.sort() # Sort by timestamp
        d = dict()
        for item in l5:
            if item[4] == '+':
                timestamp = item[0]
                hash_all = item[1]
                relative_path = item[2]
                hash_file = item[3]
                d[relative_path] = {'timestamp':timestamp, 'hash_all':hash_all, 'hash_file':hash_file}
            elif item[4] == '-':
                relative_path = item[2]
                if relative_path in d:
                    del d[relative_path]
            else:
                print('Don\'t know how to handle this: {}'.format(item[4]))
        return d


    def getRealFilesL5(self, compare_l5=None):
        """
        Returns a l5 formatted list of all files that are really in self.syncFolder

        @param compare_l5: If None, every file needs to be hashed. With a list comprehension the timestamp is used and a hash is only generated if the timestamps don't match
        @type compare_l5: list
        @return: l5-formatted list of all files that are really in self.syncFolder
        """
        self.debug('Get real files and return l5 list')
        compare_dict = {}
        if compare_l5 is not None:
            compare_dict = self.genDictFromL5(compare_l5)            
        # Get files
        files = []
        for root, dirnames, filenames in os.walk(self.syncFolder):
            for filename in filenames:
                files.append(os.path.join(root, filename))
        # Create l5 list
        l5 = []
        for filename in files:
            timestamp = os.path.getmtime(filename)
            relative_path = filename.split(self.syncFolder)[1][1:]
            hash_file = None
            if relative_path in compare_dict and self.useTimestamp is True:
                self.debug('  Use timestamp comparison for {}'.format(relative_path))
                if timestamp == compare_dict[relative_path]['timestamp']:
                    self.debug('    They match! Speedup, yeah!')
                    hash_file = compare_dict[relative_path]['hash_file']
                    
                else:  
                    self.debug('    They don\'t match, generate hashsum as fallback')
                    hash_file = self.getHashOfFile(filename)
            else:
                hash_file = self.getHashOfFile(filename)
            l5.append([timestamp, None, relative_path, hash_file, '+'])
        # Return
        return l5


    def pull(self, remotePath):
        """
        Pulls a file from remotePath into self.cacheDown/filename via SFTP
        
        @param remotePath: Absolute path of the remote file
        @type serverPath: str
        @return: Returns the absolute path of the local file 
        """
        filename = os.path.basename(remotePath)
        localPath = os.path.join(self.cacheDown, filename)
        self.sftp.get(remotePath, localPath)
        return localPath


    def push(self, localPath, remotePath):
        """
        Pushes a file from localPath to remotePath via SFTP
        
        @param localPath: Absolute path of the local file
        @type localPath: str
        @param remotePath: Absolute path of the remote file
        @type serverPath: str
        """
        self.sftp.put(localPath, remotePath, confirm=True)


    def encryptFile(self, fin, fname, passphrase):
        """
        Reads the file from $fin, encrypts it with the $passphrase and stores it into $fout
        If fin == fout the input file will be overwritten

        @param fin: Relative path for the input file
        @type fin: str
        @param fname: File name for output file, path is self.cacheUp/fname
        @type fout: str
        @param passphrase: Passphrase for encryption
        @type passphrase: str
        @return: Returns file output path ($self.cacheUp/fname)
        """
        fread = os.path.join(self.syncFolder, fin)
        fwrite = os.path.join(self.cacheUp, fname)
        # If file already exists, return
        if os.path.exists(fwrite):
            return fwrite
        # Else encrypt it
        with open(fread, 'rb') as fstreamread:
            binary = self.gpg.encrypt(fstreamread.read(), passphrase=passphrase, armor=False, encrypt=False, symmetric=True, always_trust=True, cipher_algo='AES256', compress_algo='Uncompressed') # , output=fstreamwrite) # fails with buffer interface error
            with open(fwrite, 'wb') as fstreamwrite:
                fstreamwrite.write(binary.data)
        # And return
        return fwrite

    
    def decryptFile(self, fin, fout, passphrase):
        """
        Reads the file from $fin, decrypts it with the $passphrase and stores it into $fout
        If fin == fout the input file will be overwritten

        @param fin: Absolute path for the input file
        @type fin: str
        @param fout: Absolute path for the output file (should be within self.cache if possible)
        @type fout: str
        @param passphrase: Passphrase for decryption
        @type passphrase: str
        """
        pass


    def serverFileExists(self, server_path_relative):
        """
        Returns true if $self.serverPath/$server_path_relative exists

        @param server_path_relative: The relative path to the file on the server
        @type server_path_relative: str
        @return: Returns True if the file exists and False if not
        """
        try:
            self.sftp.stat(os.path.join(self.serverPath, server_path_relative))
        except IOError as e:
            if e.errno == errno.ENOENT: # No such file or directory | http://stackoverflow.com/questions/850749/check-whether-a-path-exists-on-a-remote-host-using-paramiko
                return False
            raise e
        return True


    def sync(self):
        """
        Full sync between client and server
        """
        self.debug('Full sync')
        # If client.log exists
        if os.path.exists(self.clientLog):
            # Open client.log
            client_l5 = self.loadClientLog()
            # Load real files
            real_l5 = self.getRealFilesL5(client_l5)
            # Generate dicts
            client_dict = self.genDictFromL5(client_l5)
            real_dict = self.genDictFromL5(real_l5)
            # Merge
            diff_l5 = []
            # Get removed
            for key in client_dict:
                if not key in real_dict:
                    timestamp = client_dict[key]['timestamp']
                    hash_all  = client_dict[key]['hash_all']
                    hash_file = client_dict[key]['hash_file']
                    diff_l5.append([timestamp, hash_all, key, hash_file, '-'])
            # Get added and changed
            for key in real_dict:
                if key in client_dict:
                    if real_dict[key]['timestamp'] == client_dict[key]['timestamp']:
                        pass
                    elif real_dict[key]['hash_file'] == client_dict[key]['hash_file']:
                        pass
                    else:
                        timestamp = client_dict[key]['timestamp']
                        hash_all  = client_dict[key]['hash_all']
                        hash_file = client_dict[key]['hash_file']
                        diff_l5.append([timestamp, hash_all, key, hash_file, '-'])
                        timestamp = real_dict[key]['timestamp']
                        hash_all  = real_dict[key]['hash_all']
                        hash_file = real_dict[key]['hash_file']
                        diff_l5.append([timestamp, hash_all, key, hash_file, '+'])
                else:
                    timestamp = real_dict[key]['timestamp']
                    hash_all  = real_dict[key]['hash_all']
                    hash_file = real_dict[key]['hash_file']
                    diff_l5.append([timestamp, hash_all, key, hash_file, '+'])
            # Merge lists
            new_l5 = []
            new_l5.extend(client_l5)
            new_l5.extend(diff_l5)
            # Store
            self.storeClientLog(new_l5)
        # If client.log doesn't exist
        else:
            # Load real files
            real_l5 = self.getRealFilesL5(client_l5)
            # Store
            self.storeClientLog(real_l5)
        # Connect
        self.connect()
        # Lock
        self.lock()
        # If server.log exists
        if self.serverFileExists('server.log'):
            # Download, decrypt and open server.log
            server_log = self.pull(os.path.join(self.serverPath, 'server.log'), os.path.join(self.cacheDown, 'server.log'))
            self.decrypt(server_log, server_log, self.masterKey)
            server_l5 = None
            with open(server_log, 'r') as f:
                data = f.read()
                server_l5 = json.loads(data)
            # Open client.log
            client_l5 = self.loadClientLog()
            # Merge files
            
            # Generate diffs?!

            # Sync

            # Whatever
            

            # Generate dicts
            #server_dict = self.genDictFromL5(real_l5)
            #client_dict = self.genDictFromL5(client_l5)
            ## Merge
            #diff_l5 = []
            ## Get removed
            #for key in client_dict:
            #    if not key in server_dict:
            #        timestamp = client_dict[key]['timestamp']
            #        hash_all  = client_dict[key]['hash_all']
            #        hash_file = client_dict[key]['hash_file']
            #        diff_l5.append([timestamp, hash_all, key, hash_file, '-'])
            ## Get added and changed
            #for key in real_dict:
            #    if key in client_dict:
            #        if real_dict[key]['timestamp'] == client_dict[key]['timestamp']:
            #            pass
            #        elif real_dict[key]['hash_file'] == client_dict[key]['hash_file']:
            #            pass
            #        else:
            #            timestamp = client_dict[key]['timestamp']
            #            hash_all  = client_dict[key]['hash_all']
            ##           hash_file = client_dict[key]['hash_file']
            #            diff_l5.append([timestamp, hash_all, key, hash_file, '-'])
            #            timestamp = real_dict[key]['timestamp']
            #            hash_all  = real_dict[key]['hash_all']
            #            hash_file = real_dict[key]['hash_file']
            #            diff_l5.append([timestamp, hash_all, key, hash_file, '+'])
            #    else:
            #        timestamp = real_dict[key]['timestamp']
            #        hash_all  = real_dict[key]['hash_all']
            #        hash_file = real_dict[key]['hash_file']
            #        diff_l5.append([timestamp, hash_all, key, hash_file, '+'])
            ## Merge lists
            #new_l5 = []
            #new_l5.extend(client_l5)
            #new_l5.extend(diff_l5)
            # Store
            #self.storeClientLog(new_l5)


            # Create diff between client and server
        
            # Download/Upload files
        
            # Upload new server.log


        # If server.log doesn't exist
        else:
            # Open client.log
            client_l5 = self.loadClientLog()
            # Generate dict
            client_dict = self.genDictFromL5(client_l5)
            # Diff for upload?!
            diff_l5 = []
            # Add
            for path in client_dict:
                    timestamp = real_dict[path]['timestamp']
                    hash_all  = real_dict[path]['hash_all']
                    hash_file = real_dict[path]['hash_file']
                    diff_l5.append([timestamp, hash_all, path, hash_file, '+'])
            # Sync every entry in diff_l5:
            for item in diff_l5:
                #print(item)
                if item[4] == '+':
                    self.debug('  Push {}'.format(item[3]))
                    # Encrypt
                    localPath = self.encryptFile(item[2], item[3], self.getKey(item[3]))
                    # Push
                    remotePath = os.path.join(self.serverPath, 'files', item[3])
                    #self.sftp.put(localPath, remotePath, confirm=True)
                    self.push(localPath, remotePath)
                else:
                    self.debug('Well, erm, shit: {}'.format(entry))
            # Update server.log, this should happen on a per file basis
            serverLogPath = os.path.join(self.serverPath, 'server.log')
            with self.sftp.open(serverLogPath, 'w') as f:
                json.dump(client_l5, f, indent=2)
        # Unlock
        self.unlock()
        # Disconnect
        self.disconnect()
        # Done
        self.debug('Full sync done') #*knocks itself on her virtual shoulder*')


    def getKey(self, hash):
        """
        Return key for en-/decryption based on the given hash

        @param hash: The key-value
        @param hash: str
        @return: Returns a key for en-/decryption
        """
        # Look in key.conf for for key

        # If not found, generate a new key

        # Return key
        return 'A sample key'


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
