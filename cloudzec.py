#!/usr/bin/env python3
# -*- coding: utf-8 -*-


## Readme | http://cloudzec.org
#
# This is the basic CloudZec Class
#
# Note : First compress, then encrypt
#      : First remove, then add
#
#
## GnuPG | python-gnupg fork | Fast development, including security patches, etc.
#  https://github.com/isislovecruft/python-gnupg/
#  https://python-gnupg.readthedocs.org/en/latest/gnupg.html#gnupg-module
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
#    pw               The passphrase
#   --no-tty         Make sure that the TTY is never used for any output
#    fin              The input file
# decryption:
#  gpg
#   --decrypt        Decrypt file
#   --output         Write output to a file
#    fout             The file
#   --batch          Batch mode, don't ask for anything, do not allow interactive commands
#   --passphrase     Use string as the passphrase
#    pw               The passphrase
#   --no-tty         Make sure that the TTY is never used for any output)
#    fin              The input file
#
#
## Server structure
# $serverpath
# |-- files
# |-- lock
# |-- remote.keys   (encrypted)
# `-- remote.log    (encrypted) server.log
#
#
## Local structure
# $syncFolder
# $confFolder
#  .
#  |-- cache
#  |   |-- pull     download
#  |   `-- push     upload
#  |-- local.keys
#  |-- local.log    client.log
#  |-- cloudzec.conf
#  `-- masterkey
#
#
## local.log and remote.log | encrypted with masterkey | l4-format
#
# [
#   [timestamp, 'path', 'hash_file', 'action'],
# ]
#
## The l4-format is a list in the following specification, sorted by its timestamp (first element)
#
# List index
# 0  - float  | Modification-time of the file in UNIX-format, from os.path.getmtime(path) or time.time()
# 1  - string | Relative path of file, e.g. folder/file1.txt
# 2  - string | Hashsum of file
# 3  - string | Action, can either be + or -
#


## Imports
import getpass
import hashlib
import json
import os
import platform
import random
import string
#import tarfile
#import time
import errno
import shutil
# External
import gnupg
import paramiko


## Class
class CloudZec:
    def __init__(self, username=None, identFile=None, host='cloudzec.org', port=22, fingerprint=None, serverPath=None, allocSync=True, genMasterKey=False, debug=False):
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
        self.syncKeys = True    # Sync keys with the remote node only if self.syncKeys is True
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
            # Don't ask anything in __init__()
            raise Exception('You need to set a username in {}'.format(self.confFile))
        # Check serverPath | path like /home/$username/cloudzec on the server!
        if self.serverPath is None:
            self.debug('Create default serverPath')
            # TODO: Use a relative path like ~/cloudzec/ on the server
            self.serverPath = os.path.join('/home', self.username, 'cloudzec')
            rewrite = True
        # Rewrite if needed
        if rewrite:
            self.storeConfiguration()
        # Create gpg instance | needs to be defined before en/decrypting anything
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
        with open(self.confFile, 'r') as fIn:
            conf = json.load(fIn)
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
        with open(self.confFile, 'w') as fOut:
                json.dump(conf, fOut, sort_keys=True, indent=2)


    def loadMasterKey(self, genMasterKey=False):
        """
        Loads master key into self.masterKey, if genMasterKey is True and no key was found, key will be generated and storeMasterKey will be called

        @param genMasterKey: If True, master key is generated if not avaliable
        @type genMasterKey: bool
        """
        self.debug('Load master key')
        if os.path.exists(self.keyFile):
            data = None
            with open(self.keyFile, 'r') as fIn:
                data = fIn.read()
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
        with open(self.keyFile, 'w') as fOut:
            json.dump(self.masterKey, fOut, sort_keys=True, indent=2)


    def loadKeys(self):
        """
        Load keys into self.keys
        """
        self.debug('Load keys')
        if os.path.exists(self.keysFile):
            with open(self.keysFile, 'r') as fIn:
                #enc = fIn.read()
                #data = self.gpg.decrypt(enc, passphrase=self.masterKey)
                #data = data.data # Just the encrypted data, nothing else
                #self.keys = json.loads(data.decode('utf-8'))
                self.keys = json.load(fIn)
        else:
            #self.keys = {}
            self.storeKeys()


    def storeKeys(self, keys=None):
        """
        Store keys into self.keysFile
        """
        self.debug('Store keys')
        if keys is not None:
            self.keys = keys
        # Either use open(self.keysFile, 'wb') or use enc.decode('utf-8'). Both are ugly hacks
        with open(self.keysFile, 'w') as fOut:
            #data = json.dumps(self.keys)
            #enc = self.gpg.encrypt(data, passphrase=self.masterKey, armor=True, encrypt=False, symmetric=True, cipher_algo=self.encryption, compress_algo='Uncompressed')
            #enc = enc.data # Just the encrypted data, nothing else
            #fOut.write(enc.decode('utf-8'))
            json.dump(self.keys, fOut, sort_keys=True, indent=2)


    def getKey(self, keyHash):
        """
        Return key for en-/decryption based on the given hash

        @param keyHash: The key-value
        @param keyHash: str
        @return: Returns a key for en-/decryption
        """
        if keyHash in self.keys:
            return self.keys[keyHash]
        else:
            self.keys[keyHash] = self.genSymKey()
            self.storeKeys()
            return self.keys[keyHash]


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


    def loadLocalLog(self):
        """
        Loads client.log from self.clientLog and returns it

        @return: Returns list in l4 format
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


    def storeLocalLog(self, log):
        """
        Stores client into self.clientLog

        @param log: list in l4 format
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
            name = json.loads(data)
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


    def getHashOfFile(self, path_absolute):
        """
        Generates hashsum of a file and returns it

        @param path: path to the file (absolute)
        @type path: str
        @return: Returns hash_file in .hexdigest()-format
        """
        self.debug('Get hash of file: {}'.format(path_absolute))
        #exec('hash_file = hashlib.{}()'.format(self.hashalgorithm)) # Executes for example h = hashlib.sha256(), hash algorithm is set via self.hashalgorithm() in __init__()
        hash_file = hashlib.sha256() # TODO: Make it fucking dynamic!
        with open(path_absolute, mode='rb') as f:
            while True:
                buf = f.read(4096) # TODO: Maybe increase buffer-size for higher speed?!
                if not buf:
                    break
                hash_file.update(buf)
        return hash_file.hexdigest()


    def genDictFroml4(self, l4):
        """
        Generates a dictionary from an l4 formatted list

        @param l4: l4 style list
        @type l4: list
        @return: Returns a dictionary
        """
        self.debug('Generate dict from l4-format list')
        l4.sort() # Sort by timestamp
        d = dict()
        for item in l4:
            if item[3] == '+':
                timestamp = item[0]
                relative_path = item[1]
                hash_file = item[2]
                d[relative_path] = {'timestamp':timestamp, 'hash_file':hash_file}
            elif item[3] == '-':
                relative_path = item[1]
                if relative_path in d:
                    del d[relative_path]
            else:
                print('Don\'t know how to handle this: {}'.format(item))
        return d


    def getRealFilesl4(self, comparel4=None):
        """
        Returns a l4 formatted list of all files that are really in self.syncFolder

        @param comparel4: If None, every file needs to be hashed. With a list comprehension the timestamp is used and a hash is only generated if the timestamps don't match
        @type comparel4: list
        @return: l4-formatted list of all files that are really in self.syncFolder
        """
        self.debug('Get real files and return l4 list')
        compareDict = {}
        if comparel4 is not None:
            compareDict = self.genDictFroml4(comparel4)            
        # Get files
        files = []
        for root, dirnames, filenames in os.walk(self.syncFolder):
            for filename in filenames:
                files.append(os.path.join(root, filename))
        # Create l4 list
        l4 = []
        for filename in files:
            timestamp = os.path.getmtime(filename)
            relativePath = filename.split(self.syncFolder)[1][1:]
            hashFile = None
            if relativePath in compareDict and self.useTimestamp is True:
                self.debug('  Use timestamp comparison for {}'.format(relativePath))
                if timestamp == compareDict[relativePath]['timestamp']:
                    self.debug('    They match! Speedup, yeah!')
                    hashFile = compareDict[relativePath]['hash_file']
                    
                else:  
                    self.debug('    They don\'t match, generate hashsum as fallback')
                    hashFile = self.getHashOfFile(filename)
            else:
                hashFile = self.getHashOfFile(filename)
            l4.append([timestamp, relativePath, hashFile, '+'])
        # Return
        return l4


    def pull(self, remotePath):
        """
        Pulls a file from remotePath into self.cacheDown/filename via SFTP
        
        @param remotePath: Absolute path of the remote file
        @type serverPath: str
        @return: Returns the absolute path of the local file 
        """
        filename = os.path.basename(remotePath)
        localPath = os.path.join(self.cacheDown, filename)
        # TODO: Use callback for resume on failed transfers http://www.lag.net/paramiko/docs/paramiko.SFTPClient-class.html#get
        self.sftp.get(remotePath, localPath, callback=None)
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


    # TODO: Refactor
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
        self.debug('Encrypt file: {}'.format(fin))
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

    
    # TODO: Refactor
    def decryptFile(self, pathEnc, passphrase=None, cleanup=True):
        """
        Reads the file from $fIn, decrypts it and returns the path to the decrypted file

        @param fIn: Absolute path to the input file
        @type fIn: str
        @param passphrase: Passphrase for decryption or None if key is in self.getKey()
        @type passphrase: str
        @param cleanup: If True, the input file will be removed after decryption 
        @type cleanup: bool
        """
        fName = os.path.basename(pathEnc)
        pathDec = os.path.join(self.cache, fName)
        self.debug('Decrypt file: {}'.format(fName))
        if passphrase is None:
            passphrase = self.getKey(fName)
        with open(pathEnc, 'rb') as fIn:
            binary = self.gpg.decrypt(fIn.read(), passphrase=passphrase)    # TODO: Write direct to a file without using 2 streams
            with open(pathDec, 'wb') as fOut:
                fOut.write(binary.data)
        if cleanup:
            os.remove(pathEnc)
        return pathDec
        
        
        if os.path.exists(self.keysFile):
            with open(self.keysFile, 'r') as fIn:
                #enc = fIn.read()
                #data = self.gpg.decrypt(enc, passphrase=self.masterKey)
                #data = data.data # Just the encrypted data, nothing else
                #self.keys = json.loads(data.decode('utf-8'))
                self.keys = json.load(fIn)
        else:
            #self.keys = {}
            self.storeKeys()


    def remoteFileExists(self, serverPathRel):
        """
        Returns true if $self.serverPath/$serverPathRel exists

        @param serverPathRel: The relative path to the file on the server
        @type serverPathRel: str
        @return: Returns True if the file exists and False if not
        """
        try:
            self.sftp.stat(os.path.join(self.serverPath, serverPathRel))
        except IOError as e:
            if e.errno == errno.ENOENT: # No such file or directory | http://stackoverflow.com/questions/850749/check-whether-a-path-exists-on-a-remote-host-using-paramiko
                return False
            raise e
        return True


    # TODO: Refactor
    def sync(self):
        """
        Full sync between client and server
        """
        self.debug('Full sync')
        ## Real files -> Local files
        # If client.log exists
        if os.path.exists(self.clientLog):
            # Open client.log
            client_l4 = self.loadLocalLog()
            # Load real files
            real_l4 = self.getRealFilesl4(client_l4)
            # Generate dicts
            client_dict = self.genDictFroml4(client_l4)
            real_dict = self.genDictFroml4(real_l4)
            # Merge
            diff_l4 = []
            # Get removed
            for key in client_dict:
                if not key in real_dict:
                    timestamp = client_dict[key]['timestamp']
                    hash_file = client_dict[key]['hash_file']
                    diff_l4.append([timestamp, key, hash_file, '-'])
            # Get added and changed
            for key in real_dict:
                if key in client_dict:
                    if real_dict[key]['timestamp'] == client_dict[key]['timestamp']:
                        pass
                    elif real_dict[key]['hash_file'] == client_dict[key]['hash_file']:
                        pass
                    else:
                        timestamp = client_dict[key]['timestamp']
                        hash_file = client_dict[key]['hash_file']
                        diff_l4.append([timestamp, key, hash_file, '-'])
                        timestamp = real_dict[key]['timestamp']
                        hash_file = real_dict[key]['hash_file']
                        diff_l4.append([timestamp, key, hash_file, '+'])
                else:
                    timestamp = real_dict[key]['timestamp']
                    hash_file = real_dict[key]['hash_file']
                    diff_l4.append([timestamp, key, hash_file, '+'])
            # Merge lists
            new_l4 = []
            new_l4.extend(client_l4)
            new_l4.extend(diff_l4)
            # Store
            self.storeLocalLog(new_l4)
        # If client.log doesn't exist
        else:
            # Load real files
            real_l4 = self.getRealFilesl4()
            # Store
            self.storeLocalLog(real_l4)
        ## Local files <-> Server files
        # Connect
        self.connect()
        # Lock
        self.lock()
        # Open remote.log
        remote_l4 = []
        if self.remoteFileExists('server.log'):
            remote_l4 = []
            # Pull server.log and decrypt it
            remoteLogPath = self.pull(os.path.join(self.serverPath, 'server.log'))
            localLogPath = self.decryptFile(remoteLogPath, passphrase=self.masterKey)
            # Read it
            with open(localLogPath, 'r') as fIn:
                remote_l4 = json.load(fIn)
        # Open local.log
        local_l4 = self.loadLocalLog()
        ## Create „target“ list using a fu***** bad algorithm
        target_l4 = []
        merge_dict = {}
        for item in local_l4:
            key = '{}{}{}{}'.format(item[0], item[1], item[2], item[3])
            merge_dict[key] = item
        for item in remote_l4:
            key = '{}{}{}{}'.format(item[0], item[1], item[2], item[3])
            merge_dict[key] = item
        for key in merge_dict:
            target_l4.extend([merge_dict[key]])
        target_l4.sort()
        # Generate dicts
        remote_dict = self.genDictFroml4(remote_l4)
        local_dict = self.genDictFroml4(local_l4)
        target_dict = self.genDictFroml4(target_l4)
        ## Merge number 1: Update the local repository
        diff_l4 = self.createDiffFromDict(local_dict, target_dict)
        for item in diff_l4:
            if item[3] == '-':      # Remove from local repository
                self.debug('  Remove from local repository: {}'.format(item[1]))
                os.remove(os.path.join(self.syncFolder, item[1]))
            elif item[3] == '+':    # Add to local repository, pull from remote
                self.debug('  Add to local repository: {}'.format(item[1]))
                # TODO: Deduplication!
                # Pull, decrypt and move
                remoteFilePath = self.pull(os.path.join(self.serverPath, 'files', item[2]))
                localFilePath = self.decryptFile(remoteFilePath, passphrase=self.getKey(item[2]))
                localNewPath = os.path.join(self.syncFolder, item[1])
                if not os.path.exists(os.path.dirname(localNewPath)):
                    os.makedirs(os.path.dirname(localNewPath))
                shutil.move(localFilePath, localNewPath)
                #os.remove(remoteFilePath)
            else:
                print('Well, erm, shit: {}'.format(item))
        # Merge lists
        localNew_l4 = []
        localNew_l4.extend(local_l4)
        localNew_l4.extend(diff_l4)
        localNew_l4.sort()
        # Store
        self.storeLocalLog(localNew_l4)
        ## Merge number 2: Update the remote repository
        diff_l4 = self.createDiffFromDict(remote_dict, target_dict)
        for item in diff_l4:
            if item[3] == '-':
                self.debug('  Remove from remote repository: {}'.format(item[1]))
                # Do nothing at the moment :)
            elif item[3] == '+':    # Add to local repository, pull from remote
                self.debug('  Add to remote repository: {}'.format(item[1]))
                # TODO: Deduplication!
                # Encrypt and push, remove tmp file
                localPath = self.encryptFile(item[1], item[2], self.getKey(item[2]))
                remotePath = os.path.join(self.serverPath, 'files', item[2])
                self.push(localPath, remotePath)
                os.remove(localPath)
            else:
                print('Well, erm, shit: {}'.format(item))
        # Merge lists
        remoteNew_l4 = []
        remoteNew_l4.extend(local_l4)
        remoteNew_l4.extend(diff_l4)
        remoteNew_l4.sort()
        # Store
        serverLogPath = os.path.join(self.serverPath, 'server.log')
        with self.sftp.open(serverLogPath, 'w') as fOut:
            data = json.dumps(remoteNew_l4)
            enc = self.gpg.encrypt(data, passphrase=self.masterKey, armor=True, encrypt=False, symmetric=True, cipher_algo=self.encryption, compress_algo='Uncompressed')
            enc = enc.data # Just the encrypted data, nothing else
            fOut.write(enc.decode('utf-8'))
        ## Sync keys
        if self.syncKeys is True:
            # Open remote.keys
            remoteKeys = {}
            if self.remoteFileExists('remote.keys'):
                remoteKeysPath = self.pull(os.path.join(self.serverPath, 'remote.keys'))
                localKeysPath = self.decryptFile(remoteKeysPath, passphrase=self.masterKey)
                with open(localKeysPath, 'r') as fIn:
                    remoteKeys = json.load(fIn)
            # Merge with local keys
            targetKeys = {}
            for key in self.keys:
                targetKeys[key] = self.keys[key]
            for key in remoteKeys:
                if key in targetKeys:
                    if targetKeys[key] == remoteKeys[key]:
                        pass
                    else:
                        print('Damnit, Keys don\'t match for {}'.format(key))
                else:
                    targetKeys[key] = self.keys[key]
            # Store local
            self.storeKeys(targetKeys)
            # And remote            
            serverLogPath = os.path.join(self.serverPath, 'remote.keys')
            with self.sftp.open(serverLogPath, 'w') as fOut:
                data = json.dumps(targetKeys)
                enc = self.gpg.encrypt(data, passphrase=self.masterKey, armor=True, encrypt=False, symmetric=True, cipher_algo=self.encryption, compress_algo='Uncompressed')
                enc = enc.data # Just the encrypted data, nothing else
                fOut.write(enc.decode('utf-8'))
        # Unlock
        self.unlock()
        # Disconnect
        self.disconnect()
        # Done
        self.debug('Full sync done') #*knocks itself on her virtual shoulder*')


    def createDiffFromDict(self, old_dict, new_dict):
        '''
        Create a diff from the old_dict to new_dict

        @param old_dict: Old dictionary
        @type old_dict: dict
        @param new_dict: New dictionary
        @type new_dict: dict
        @return: Returns the diff as l4 formatted list
        '''
        self.debug('Create diff from dict')
        diff_l4 = []
        # Get removed
        for key in old_dict:
            if not key in new_dict:
                timestamp = old_dict[key]['timestamp']
                hash_file = old_dict[key]['hash_file']
                diff_l4.append([timestamp, key, hash_file, '-'])
        # Get added and changed
        for key in new_dict:
            if key in old_dict:
                if new_dict[key]['timestamp'] == old_dict[key]['timestamp']:
                    pass
                elif new_dict[key]['hash_file'] == old_dict[key]['hash_file']:
                    pass
                else:
                    timestamp = old_dict[key]['timestamp']
                    hash_file = old_dict[key]['hash_file']
                    diff_l4.append([timestamp, key, hash_file, '-'])
                    timestamp = new_dict[key]['timestamp']
                    hash_file = new_dict[key]['hash_file']
                    diff_l4.append([timestamp, key, hash_file, '+'])
            else:
                timestamp = new_dict[key]['timestamp']
                hash_file = new_dict[key]['hash_file']
                diff_l4.append([timestamp, key, hash_file, '+'])
        # Return
        return diff_l4
