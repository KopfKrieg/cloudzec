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
# `-- remote.log    (encrypted)
#
#
## Local structure
# $syncFolder
# $confFolder
#  .
#  |-- cache
#  |   |-- pull     (download)
#  |   `-- push     (upload)
#  |-- local.keys
#  |-- local.log
#  |-- cloudzec.conf
#  `-- masterKey
#
#
## local.log and remote.log | encrypted with masterKey | l4-format
#
# [
#   [timestamp, 'path', 'hashsum', 'action'],
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
import stat
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
    def __init__(self, genMasterKey=False, notifyCallback=None, debug=False):
        ## Basic setup
        self._debug = debug
        # Standard pathes
        home = os.path.expanduser('~')
        self.confFolder = os.path.join(home, '.cloudzec')
        self.confFile = os.path.join(self.confFolder, 'cloudzec.conf')
        self.keysFile = os.path.join(self.confFolder, 'keys')
        self.localLog = os.path.join(self.confFolder, 'local.log')
        # Empty vars
        self.masterKey = None           # Masterkey
        self.keys      = {}             # Keys for data en/decryption
        # Default configuration, use loadConfiguration() to override
        self.cache = os.path.join(self.confFolder, 'cache')
        self.cleanup = False            # If true, everything that is no longer needed will be removed from both, local and remote (keys on both repositories and files on the remote) Use with caution!
        self.compression = 'none'       # Preferred compression algorithm |"none": Uncompressed (best for binary files) |"ZIP": Zip compression, PGP-compatible |"ZLIB": Zlib compression, incompatible to PGP |"BZIP2": Bzip2 compression, only compatible with GnuPG | Choose wisely
        self.device = platform.node()   # Device name, neccessary for lock-name on server
        self.encryption = 'AES256'      # Preferred encryption algorithm
        self.hashAlgorithm = 'sha256'   # Preferred hash algorithm from hashlib:  md5, sha1, sha224, sha256, sha384, sha512
        self.host = 'cloudzec.org'      # Server host
        self.identFile = None           # Identify file for server-login, None if passwordlogin is preferred over publickey
        self.masterKeyFile = None       # None tries to find a keyring, else set a path like: os.path.join(self.confFolder, 'masterKey')
        self.port = 22                  # Server port
        self.remotePath = None          # CloudZec-folder on remote device
        self.syncFolder = os.path.join(home, 'CloudZec')    # Local sync-folder
        self.syncKeys = True            # Sync keys with the remote node only if self.syncKeys is True
        self.useTimestamp = True        # If true, a timestamp comparison is done instead of generating hashsums. This speed ups a lot but is not as good as comparing hashsums
        self.username = None            # Username for server-login
        # Create confFolder if missing
        if not os.path.exists(self.confFolder):
            self.debug('Create confFolder {}'.format(self.confFolder))
            os.makedirs(self.confFolder)
        # If confFile does not exists: Write the sample configuration-file and return
        if not os.path.exists(self.confFile):
            self.storeConfiguration()
            self.loadMasterKey(genMasterKey)
            return
        else:
            # Load configuration (and override defaults)
            self.loadConfiguration()
        # After loading the config
        self.cachePush = os.path.join(self.cache, 'push')
        self.cachePull = os.path.join(self.cache, 'pull')
        ## Check configuration
        rewrite = False
        # Check folder: cache
        if not os.path.exists(self.cache):
            self.debug('Create folder: {}'.format(self.cache))
            os.makedirs(self.cache)
        # Check folder: cachePush
        if not os.path.exists(self.cachePush):
            self.debug('Create folder: {}'.format(self.cachePush))
            os.makedirs(self.cachePush)
        # Check folder: cachePull
        if not os.path.exists(self.cachePull):
            self.debug('Create folder: {}'.format(self.cachePull))
            os.makedirs(self.cachePull)
        # Check folder: syncFolder
        if not os.path.exists(self.syncFolder):
            self.debug('Create folder: {}'.format(self.syncFolder))
            os.makedirs(self.syncFolder)
        # Check username
        if self.username is None:
            # Don't ask anything in __init__()
            raise Exception('You need to set a username in {}'.format(self.confFile))
        # Create gpg instance | needs to be defined before en/decrypting anything
        binary = '/usr/bin/gpg2' # No symlinks allowed
        homedir = os.path.join(home, '.gnupg')
        #keyring = os.path.join(homedir, 'pubring.gpg')
        #secring = os.path.join(homedir, 'secring.gpg')
        #self.gpg = gnupg.GPG(binary=binary, homedir=homedir, keyring=keyring, secring=secring)
        self.gpg = gnupg.GPG(binary=binary, homedir=homedir)
        #self.gpg.use_agent = True
        ## Set empty rng, needs to be done before loading master key
        self.rng = None
        ## Load master key | Needs to be done before storing something (encrypted)
        self.loadMasterKey(genMasterKey)
        ## Load keys
        self.loadKeys()
        # Rewrite?
        if rewrite:
            self.debug('Rewrite configuration')
            self.storeConfiguration()
        ## Enable notifications:
        self.notifyCallback = notifyCallback


    def notify(self, message):
        """
        Pass-through for notifications using a callback-mechanism

        @param message: The message of the notification
        @type message: str
        """
        if self.notifyCallback is not None:
            self.notifyCallback(message)


    def remoteTreeRemove(self, remotePath):
        """
        Removes a complete filesystem-tree on the remote host. Be careful!
        
        @param remotePath: The remote path to delete
        @type remotePath: str
        """
        for item in self.sftp.listdir_attr(remotePath):
            newPath = os.path.join(remotePath, item.filename)
            if stat.S_ISDIR(item.st_mode):
                self.remoteTreeRemove(newPath)
            else:
                self.debug('  Removing {}'.format(newPath))
                self.sftp.remove(newPath)
        self.debug('  Removing {}'.format(remotePath))
        self.sftp.rmdir(remotePath)


    def remoteinit(self):
        """
        Initialises the remote host. Caution: Deletes everything!
        """
        self.debug('Remote init')
        # Connect
        self.connect()
        # Lock
        self.lock()
        # If self.remotePath exists:
        if self.remotePathExists():
            # Clear everything in self.remotePath
            self.remoteTreeRemove(self.remotePath)
        # Setup self.remotePath
        self.sftp.mkdir(self.remotePath)
        self.sftp.mkdir(os.path.join(self.remotePath, 'files'))
        # Unlock
        self.unlock()
        # Disconnect
        self.disconnect()


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
        self.debug('Load Configuration: {}'.format(self.confFile))
        conf = None
        with open(self.confFile, 'r') as fIn:
            conf = json.load(fIn)
        rewrite = False
        keys = ['cache', 'cleanup', 'compression', 'device', 'encryption', 'hashAlgorithm', 'host', 'identFile', 'masterKeyFile', 'port', 'remotePath', 'syncFolder', 'syncKeys', 'useTimestamp', 'username']
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
        self.debug('Store Configuration: {}'.format(self.confFile))
        keys = ['cache', 'cleanup', 'compression', 'device', 'encryption', 'hashAlgorithm', 'host', 'identFile', 'masterKeyFile', 'port', 'remotePath', 'syncFolder', 'syncKeys', 'useTimestamp', 'username']
        conf = {}
        for key in keys:
            exec('conf[\'{}\'] = self.{}'.format(key, key))
        with open(self.confFile, 'w') as fOut:
                json.dump(conf, fOut, sort_keys=True, indent=2)


    def loadMasterKey(self, genMasterKey=False):
        """
        Loads master key into self.masterKey, if genMasterKey is True and no key was found, key will be generated and self.storeMasterKey() is called

        @param genMasterKey: If True, master key will be generated if not avaliable
        @type genMasterKey: bool
        """
        self.debug('Load master key: {}'.format(self.masterKeyFile))
        # Check if a keyring should be used or a file
        if self.masterKeyFile is None:
            try:
                import keyring
                self.keyring = keyring
            except ImportError as e:
                print('Couldn\'t find keyring-bindings')
                self.masterKeyFile = os.path.join(self.confFolder, 'masterKey')
                print('  Use {} as fallback'.format(self.masterKeyFile))
        # If self.masterkeyFile is still None, use the keyring
        if self.masterKeyFile is None:
            p = self.keyring.get_password('CloudZec sync', 'master')
            if p is None:   # No password stored, you should generate it
                if genMasterKey:
                    self.masterKey = self.genSymKey()
                    self.storeMasterKey()
                else:
                    raise Exception('No master key found and I am not allowed to generate a new one')
            else:
                self.masterKey = p
        # Else use a file 
        else:
            if os.path.exists(self.masterKeyFile):
                data = None
                with open(self.masterKeyFile, 'r') as fIn:
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
        Stores master key, either into a keyring or into self.masterKeyFile
        """
        self.debug('Store master key: {}'.format(self.masterKeyFile))
        if self.masterKeyFile is None:
            self.keyring.set_password('CloudZec sync', 'master', self.masterKey)
        else:
            with open(self.masterKeyFile, 'w') as fOut:
                json.dump(self.masterKey, fOut, sort_keys=True, indent=2)


    def loadKeys(self):
        """
        Load self.keys from self.keysFile
        """
        self.debug('Load keys: {}'.format(self.keysFile))
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
        Store self.keys into self.keysFile
        """
        self.debug('Store keys: {}'.format(self.keysFile))
        if keys is not None:
            self.keys = keys
        # Either use open(self.keysFile, 'wb') or use enc.decode('utf-8'). Both are ugly hacks
        with open(self.keysFile, 'w') as fOut:
            #data = json.dumps(self.keys)
            #enc = self.gpg.encrypt(data, passphrase=self.masterKey, armor=True, encrypt=False, symmetric=True, cipher_algo=self.encryption, compress_algo='Uncompressed')
            #enc = enc.data # Just the encrypted data, nothing else
            #fOut.write(enc.decode('utf-8'))
            json.dump(self.keys, fOut, sort_keys=True, indent=2)


    def getKey(self, keyHash, generateKey=True):
        """
        Return key for en-/decryption based on the given hash

        @param keyHash: The key/hash-value
        @param keyHash: str
        @param generateKey: If True, a key will be generated if required. If False an exception will be thrown
        @param keyHash: bool
        @return: Returns A key for en-/decryption
        """
        self.debug('Get key: {}'.format(keyHash))
        if keyHash in self.keys:
            return self.keys[keyHash]
        else:
            if generateKey:
                self.keys[keyHash] = self.genSymKey()
                self.storeKeys()
                return self.keys[keyHash]
            else:
                raise Exception('No key found for {}'.format(keyHash))


    def genSymKey(self, length=32):
        """
        Generates a nice symmetric key

        @param length: Length of symmetric key
        @type length: int
        @return: Returns a safe random key
        """
        self.debug('Generate symmectric key')
        # Setup (hopefully) a secure random number generator
        if self.rng is None:
            self.rng = random.SystemRandom()
        # Generate a random string
        chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(self.rng.choice(chars) for i in range(length))


    def loadLocalLog(self):
        """
        Loads local.log from self.localLog and returns it

        @return: Returns list in l4 format
        """
        self.debug('Load local log: {}'.format(self.localLog))
        local = []
        if os.path.exists(self.localLog):
            with open(self.localLog, 'r') as fIn:
                data = fIn.read()
                local = json.loads(data)
        else:
            local = []
            self.storeLocalLog(local)
        return local


    def storeLocalLog(self, log):
        """
        Stores client into self.localLog

        @param log: list in l4 format
        @type log: list
        """
        self.debug('Store local log: {}'.format(self.localLog))
        with open(self.localLog, 'w') as f:
            json.dump(log, f, indent=2)


    def connect(self):
        """
        Connect to remote host
        """
        self.debug('Connect to remote host')
        try:
            if self._transport.is_active():
                return  # Return if a transport is already opened. This could cause problems if, for example, the transport is open but the sftpclient is inactive/dead/etc
        except AttributeError:  # self._transport is not defined, so we should open it
            pass
        self._transport = paramiko.Transport((self.host, self.port))
        self.sftp = None
        if self.identFile is None:
            self.debug('  Use password login')
            try:
                self._transport.connect(username=self.username, password=getpass.getpass('    Password for remote host: '))
            except paramiko.ssh_exception.BadAuthenticationType:
                self.debug('      Hm. Login with password doesn\'t work. Did you set „identFile“ in {}?'.format(self.confFile))
                raise
        else:
            self.debug('  Use identity file for login')
            key = None
            identFile = os.path.expanduser(self.identFile)
            try:
                key = paramiko.RSAKey.from_private_key_file(identFile)
            except paramiko.ssh_exception.PasswordRequiredException:
                key = paramiko.RSAKey.from_private_key_file(identFile, password=getpass.getpass('    Password for identity file: '))
            self._transport.connect(username=self.username, pkey=key)
        self.sftp = paramiko.SFTPClient.from_transport(self._transport)
        self.debug('  Connected to remote host: {}@{}:{}'.format(self.username, self.host, self.port))
        # Check remotePath | Path like /home/$username/cloudzec on the remote device!
        if self.remotePath is None:
            self.debug('Create default remotePath')
            self.remotePath = os.path.join(self.sftp.normalize('.'), 'cloudzec')
            self.debug('  {}'.format(self.remotePath))
            self.storeConfiguration()


    def disconnect(self):
        """
        Disconnect from server
        """
        self.debug('Disconnect from remote host')
        self.sftp.close()
        self._transport.close()
        self.debug('  Disconnected from remote host')


    def getLockName(self):
        """
        Get name of lock (who locked the remote host?)

        @return: Returns the name of the device which locked the remote host
        """
        self.debug('Get lock name')
        self.sftp.chdir(self.remotePath)
        name = None
        with self.sftp.open('lock', 'r') as f:
            data = f.read()
            name = json.loads(data)
        return name


    def lock(self):
        """
        Try to lock remote directory, raises exception if remote host can't be locked
        """
        self.debug('Lock remote directory')
        self.sftp.chdir(self.remotePath)
        if 'lock' in self.sftp.listdir(self.remotePath):
            if self.device == self.getLockName():
                self.debug('  Already locked (from this device)')
            else:
                self.debug('  Already locked (from {})'.format(name))
                self.disconnect()
                raise Exception('  Cannot lock remote directory (locked by {})'.format(name))
        else:
            with self.sftp.open('lock', 'w') as f:
                json.dump(self.device, f)


    def unlock(self, override=False):
        """
        Unlocks the remote directory, if locked from another device and override is True, lock will also be removed
        """
        self.debug('Unlock remote directory')
        self.sftp.chdir(self.remotePath)
        if 'lock' in self.sftp.listdir(self.remotePath):
            if self.device == self.getLockName():
                self.sftp.remove('lock')
                self.debug('  Removed lock')
            else:
                if override:
                    self.sftp.remove('lock')
                    self.debug('  Overriding lock - removing it')
                else:
                    self.disconnect()
                    raise Exception('  Could not unlock remote directory')
        else:
            self.debug('  Remote host is not locked')


    def getHashOfFile(self, localPath):
        """
        Generates hashsum of a file and returns it

        @param localPath: Path to the file (absolute)
        @type localPath: str
        @return: Returns hashsum in .hexdigest()-format
        """
        self.debug('Get hashsum of file: {}'.format(localPath))
        hashsum = eval('hashlib.{}()'.format(self.hashAlgorithm))   # Executes for example hashsum = hashlib.sha256()
        #hashsum = hashlib.sha256()
        with open(localPath, mode='rb') as fIn:
            while True:
                buf = fIn.read(4096)    # Maybe increase buffer-size for higher speed?
                if not buf:
                    break
                hashsum.update(buf)
        return hashsum.hexdigest()


    def genDictFroml4(self, l4):
        """
        Generates a dictionary from an l4 formatted list

        @param l4: l4 style list
        @type l4: list
        @return: Returns a dictionary
        """
        self.debug('Generate dict from l4 format list')
        l4.sort() # Sort by timestamp
        d = dict()
        for entry in l4:
            if entry[3] == '+':
                timestamp = entry[0]
                relative_path = entry[1]
                hashsum = entry[2]
                d[relative_path] = {'timestamp':timestamp, 'hashsum':hashsum}
            elif entry[3] == '-':
                relativePath = entry[1]
                if relativePath in d:
                    del d[relativePath]
            else:
                print('Don\'t know how to handle this: {}'.format(item))
        return d


    def getRealFilesl4(self, comparel4=None):
        """
        Returns a l4 formatted list of all files that are really in self.syncFolder

        @param comparel4: If None, every file needs to be hashed. With a list comprehension the timestamp is used and a hashsum is only generated if the timestamps don't match
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
            hashsum = None
            if relativePath in compareDict and self.useTimestamp is True:
                self.debug('  Use timestamp comparison for {}'.format(relativePath))
                if timestamp == compareDict[relativePath]['timestamp']:
                    self.debug('    They match! Speedup, yeah!')
                    hashsum = compareDict[relativePath]['hashsum']
                else:  
                    self.debug('    They don\'t match, generate hashsum as fallback')
                    hashsum = self.getHashOfFile(filename)
            else:
                hashsum = self.getHashOfFile(filename)
            l4.append([timestamp, relativePath, hashsum, '+'])
        # Return
        return l4


    def pull(self, remotePathRel):
        """
        Pulls a file from self.remotePath/remotePathRel into self.cachePull/filename via SFTP
        
        @param remotePathRel: Relative path of the remote file
        @type remotePathRel: str
        @return: Returns the absolute path of the local file 
        """
        self.debug('Pull: {}'.format(remotePathRel))
        filename = os.path.basename(remotePathRel)
        localPath = os.path.join(self.cachePull, filename)
        remotePathAbs = os.path.join(self.remotePath, remotePathRel)
        self.sftp.get(remotePathAbs, localPath, callback=self.printTransferStat)
        return localPath


    def push(self, localPath, remotePathRel):
        """
        Pushes a file from localPath to self.remotePath/remotePathRel via SFTP
        
        @param localPath: Absolute path of the local file
        @type localPath: str
        @param remotePathRel: Relative path of the remote file
        @type remotePathRel: str
        """
        self.debug('Push: {} → {}'.format(localPath, remotePathRel))
        remotePathAbs = os.path.join(self.remotePath, remotePathRel)
        self.sftp.put(localPath, remotePathAbs, callback=self.printTransferStat, confirm=True)


    def printTransferStat(self, bytesT, bytesA):
        try:
            self.debug('  Transfer: {} of {} Bytes ({:.2f} %)'.format(bytesT, bytesA, bytesT/bytesA*100))
        except ZeroDivisionError as e:
            self.debug('F*** you: Divison by zero, this should not happen: {}/{}'.format(bytesT, bytesA))


    def encryptFile(self, pathIn, filename, passphrase, force=False):
        """
        Reads the file from pathIn, encrypts it with the passphrase and stores it into self.cachePush/filename.
        Returns the path to the new file.

        @param pathIn: Relative path of the input file
        @type pathIn: str
        @param filename: File name for output file
        @type filename: str
        @param passphrase: Passphrase for encryption
        @type passphrase: str
        @param force: If True, the file will be written, no matter if it already exists or not
        @type force: bool
        @return: Returns file output path ($self.cachePush/filename)
        """
        self.debug('Encrypt file: {} → {}'.format(pathIn, filename))
        # Create pathes
        pathIn = os.path.join(self.syncFolder, pathIn)
        pathOut = os.path.join(self.cachePush, filename)
        # If file already exists, return
        if os.path.exists(pathOut) and not force:
            return pathOut
        # Else encrypt it
        with open(pathIn, 'rb') as fIn:
            #with open(pathOut, 'wb') as fOut:
            #    self.gpg.encrypt(fIn.read(), passphrase=passphrase, armor=False, encrypt=False, symmetric=True, always_trust=True, cipher_algo='AES256', compress_algo='Uncompressed', output=fOut)
            binary = self.gpg.encrypt(fIn.read(), passphrase=passphrase, armor=False, encrypt=False, symmetric=True, always_trust=True, cipher_algo='AES256', compress_algo=self.compression)
            with open(pathOut, 'wb') as fOut:
                fOut.write(binary.data)
        # And return
        return pathOut

    
    def decryptFile(self, pathIn, passphrase=None, cleanup=True):
        """
        Reads the file from pathIn, decrypts it and returns the path to the decrypted file

        @param pathIn: Absolute path to the input file
        @type pathIn: str
        @param passphrase: Passphrase for decryption or None if key is in self.getKey()
        @type passphrase: str
        @param cleanup: If True, the input file will be removed after decryption 
        @type cleanup: bool
        """
        filename = os.path.basename(pathIn)
        pathOut = os.path.join(self.cache, filename)
        self.debug('Decrypt file: {}'.format(filename))
        if passphrase is None:
            passphrase = self.getKey(filename, generateKey=False)
        with open(pathIn, 'rb') as fIn:
            binary = self.gpg.decrypt(fIn.read(), passphrase=passphrase)
            with open(pathOut, 'wb') as fOut:
                fOut.write(binary.data)
        if cleanup:
            os.remove(pathIn)
        return pathOut
        

    def remotePathExists(self, remotePathRel=''):
        """
        Returns True if $self.remotePath/remotePathRel exists

        @param remotePathRel: The relative path to the file on the server
        @type remotePathRel: str
        @return: Returns True if the file exists and False if not
        """
        self.debug('Remote path exists: {}'.format(os.path.join(self.remotePath, remotePathRel)))
        try:
            self.sftp.stat(os.path.join(self.remotePath, remotePathRel))
        except IOError as e:
            if e.errno == errno.ENOENT: # No such file or directory | http://stackoverflow.com/questions/850749/check-whether-a-path-exists-on-a-remote-host-using-paramiko
                return False
            raise e
        return True


    def syncKeysWithRemote(self, cleanup=False, keys=None):
        """
        Synchronises keys with remote if self.syncKeys is True, also stores the merged list of keys on the local repository using self.storeKeys()
        If cleanup is True, all keys that are no longer needed will be removed (using the list of hashsum/keys as reference)

        @param cleanup: If True only required keys are stored
        @type cleanup: bool
        @param keys: A list of hashsums/keys/whatever to keep
        @param keys: list
        """
        if self.syncKeys is True:
            self.debug('Sync keys')
            # Open remote.keys
            remoteKeys = {}
            if self.remotePathExists('remote.keys'):
                remoteKeysPath = self.pull('remote.keys')
                localKeysPath = self.decryptFile(remoteKeysPath, passphrase=self.masterKey)
                with open(localKeysPath, 'r') as fIn:
                    remoteKeys = json.load(fIn)
                # Remove tmpfile
                os.remove(localKeysPath)
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
                    targetKeys[key] = remoteKeys[key]
            # Cleanup if cleanup is True and keys is not None
            if cleanup is True and keys is not None:
                self.debug('  Cleaning up keys…')
                newTargetKeys = {}
                for key in targetKeys:
                    if key in keys:
                        newTargetKeys[key] = targetKeys[key]
                    else:
                        self.debug('    Throwing away key for {}'.format(key))
                targetKeys = newTargetKeys  # Caution: This is not a deepcopy
            ## Only do write-operations if anything changed
            # On local
            if not targetKeys == self.keys:     # This is not super-reliable
                self.storeKeys(targetKeys)
            # And remote
            if not targetKeys == remoteKeys:    # This is not super-reliable
                serverLogPath = os.path.join(self.remotePath, 'remote.keys')
                with self.sftp.open(serverLogPath, 'w') as fOut:
                    data = json.dumps(targetKeys)
                    enc = self.gpg.encrypt(data, passphrase=self.masterKey, armor=True, encrypt=False, symmetric=True, cipher_algo=self.encryption, compress_algo='ZIP')
                    enc = enc.data # Just the encrypted data, nothing else
                    fOut.write(enc.decode('utf-8'))


    def createDiffFromDict(self, oldDict, newDict):
        """
        Create a diff from the oldDict to newDict

        @param oldDict: Old dictionary
        @type oldDict: dict
        @param newDict: New dictionary
        @type newDict: dict
        @return: Returns the diff as l4 formatted list
        """
        self.debug('Create diff from dict')
        diff_l4 = []
        # Get removed
        for key in oldDict:
            if not key in newDict:
                timestamp = oldDict[key]['timestamp']
                hashsum = oldDict[key]['hashsum']
                diff_l4.append([timestamp, key, hashsum, '-'])
        # Get added and changed
        for key in newDict:
            if key in oldDict:
                if newDict[key]['timestamp'] == oldDict[key]['timestamp']:
                    pass
                elif newDict[key]['hashsum'] == oldDict[key]['hashsum']:
                    pass
                else:
                    timestamp = oldDict[key]['timestamp']
                    hashsum = oldDict[key]['hashsum']
                    diff_l4.append([timestamp, key, hashsum, '-'])
                    timestamp = newDict[key]['timestamp']
                    hashsum = newDict[key]['hashsum']
                    diff_l4.append([timestamp, key, hashsum, '+'])
            else:
                timestamp = newDict[key]['timestamp']
                hashsum = newDict[key]['hashsum']
                diff_l4.append([timestamp, key, hashsum, '+'])
        # Return
        return diff_l4


    def sync1(self):
        """
        Full sync between local and remote repository, version 1
        """
        self.debug('Full sync')
        ## Real files -> Local files
        self.debug('  Syncing real files and local files')
        # Open local.log
        local_l4 = self.loadLocalLog()
        # Load real files
        real_l4 = self.getRealFilesl4(local_l4)
        # Generate dicts
        local_dict = self.genDictFroml4(local_l4)
        real_dict = self.genDictFroml4(real_l4)
        # Generate diff
        diff_l4 = self.createDiffFromDict(local_dict, real_dict)
        # Merge lists
        new_l4 = []
        new_l4.extend(local_l4)
        new_l4.extend(diff_l4)
        # Store
        self.storeLocalLog(new_l4)
        ## Local files <-> Remote files
        self.debug('  Syncing local files and remote files')
        # Connect
        self.connect()
        # Lock
        self.lock()
        # Open remote.log
        remote_l4 = []
        if self.remotePathExists('remote.log'):
            remote_l4 = []
            # Pull remote.log and decrypt it
            remoteLogPath = self.pull('remote.log')
            localLogPath = self.decryptFile(remoteLogPath, passphrase=self.masterKey)
            # Read it
            with open(localLogPath, 'r') as fIn:
                remote_l4 = json.load(fIn)
            # Remove tmpfile
            os.remove(localLogPath)
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
        ## Sync keys before syncing files, otherwise decryption with files from remote to local will throw an exception
        self.syncKeysWithRemote(cleanup=False)
        ## Merge number 1: Update the local repository
        self.debug('    Update the local repository')
        diff_l4 = self.createDiffFromDict(local_dict, target_dict)
        for item in diff_l4:
            if item[3] == '-':      # Remove from local repository
                self.debug('  Remove from local repository: {}'.format(item[1]))
                os.remove(os.path.join(self.syncFolder, item[1]))
            elif item[3] == '+':    # Add to local repository, pull from remote
                self.debug('  Add to local repository: {}'.format(item[1]))
                # Pull, decrypt and move
                remoteFilePath = self.pull(os.path.join('files', item[2]))
                localFilePath = self.decryptFile(remoteFilePath, passphrase=self.getKey(item[2], generateKey=False))
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
        self.debug('    Update the remote repository')
        diff_l4 = self.createDiffFromDict(remote_dict, target_dict)
        for item in diff_l4:
            if item[3] == '-':
                self.debug('  Remove from remote repository: {}'.format(item[1]))
                # Do nothing at the moment :)
            elif item[3] == '+':    # Add to local repository, pull from remote
                self.debug('  Add to remote repository: {}'.format(item[1]))
                # Encrypt and push, remove tmp file
                localPath = self.encryptFile(item[1], item[2], self.getKey(item[2]))
                remotePath = os.path.join('files', item[2])
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
        serverLogPath = os.path.join(self.remotePath, 'remote.log')
        with self.sftp.open(serverLogPath, 'w') as fOut:
            data = json.dumps(remoteNew_l4)
            enc = self.gpg.encrypt(data, passphrase=self.masterKey, armor=True, encrypt=False, symmetric=True, cipher_algo=self.encryption, compress_algo='Uncompressed')
            enc = enc.data # Just the encrypted data, nothing else
            fOut.write(enc.decode('utf-8'))
        ## Sync keys
        self.syncKeysWithRemote(cleanup=self.cleanup)
        # Unlock
        self.unlock()
        # Disconnect
        self.disconnect()
        # Done
        self.debug('Full sync done') #*knocks itself on her virtual shoulder*')


    def sync(self):
        """
        Full sync between local and remote repository, version 2 using a queue and notifcations
        """
        self.debug('Full sync')
        self.notify('Starting full sync…')
        ## Real files -> Local files
        self.debug('  Syncing real files and local files')
        # Open local.log
        local_l4 = self.loadLocalLog()
        # Load real files
        real_l4 = self.getRealFilesl4(local_l4)
        # Generate dicts
        local_dict = self.genDictFroml4(local_l4)
        real_dict = self.genDictFroml4(real_l4)
        # Generate diff
        diff_l4 = self.createDiffFromDict(local_dict, real_dict)
        # Merge lists
        new_l4 = []
        new_l4.extend(local_l4)
        new_l4.extend(diff_l4)
        # Store
        self.storeLocalLog(new_l4)
        ## Local files <-> Remote files
        self.debug('  Syncing local files and remote files')
        # Connect
        self.connect()
        # Lock
        self.lock()
        # Open remote.log
        remote_l4 = []
        if self.remotePathExists('remote.log'):
            remote_l4 = []
            # Pull remote.log and decrypt it
            remoteLogPath = self.pull('remote.log')
            localLogPath = self.decryptFile(remoteLogPath, passphrase=self.masterKey)
            # Read it
            with open(localLogPath, 'r') as fIn:
                remote_l4 = json.load(fIn)
            # Remove tmpfile
            os.remove(localLogPath)
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
        ## Sync keys before syncing files, otherwise decryption with files from remote to local will throw an exception
        self.syncKeysWithRemote(cleanup=False)
        ## Merge number 1: Update the local repository
        self.debug('    Update the local repository')
        # Get files to remove and add
        diff_l4 = self.createDiffFromDict(local_dict, target_dict)
        if diff_l4: # If diff_l4 is not empty
            self.notify('      Updating {} files in the local repository'.format(len(diff_l4)))
        queuePull_l4 = []
        for item in diff_l4:
            if item[3] == '-':      # Remove from local repository
                self.debug('      Remove from local repository: {}'.format(item[1]))
                localFilePath = os.path.join(self.syncFolder, item[1])
                os.remove(localFilePath)
                # Remove emtpy folder
                localDirPath = os.path.dirname(localFilePath)
                if not os.listdir(localDirPath):  # If a list is empty, its boolean value is False
                    self.debug('      Remove empty directory')
                    os.rmdir(localDirPath)
            elif item[3] == '+':    # Add to local repository, pull from remote
                queuePull_l4.append(item)
            else:
                print('      Well, erm, shit: {}'.format(item))
        # Create a list of unique items to pull
        queuePull_list = []
        for item in queuePull_l4:
            if not item[2] in queuePull_list:
                queuePull_list.append(item[2])
        len_list = len(queuePull_list)
        len_l4 = len(queuePull_l4)
        # Pull and decrypt
        pathes = []
        index = 0
        for hashsum in queuePull_list:
            #self.notify('Pull and decrypt file {} of {}, {:.2f}% done'.format(index, len_list, index/len_list*100))
            self.debug(hashsum)
            remoteFilePath = self.pull(os.path.join('files', hashsum))
            localFilePath = self.decryptFile(remoteFilePath, passphrase=self.getKey(hashsum, generateKey=False))
            pathes.append(localFilePath)
            index += 1
        # Copying
        index = 0
        for item in queuePull_l4:
            #self.notify('Moving file {} of {}, {:.2f}% done'.format(index, len_l4, index/len_l4*100))
            localFilePath = os.path.join(self.cache, item[2])
            localNewPath = os.path.join(self.syncFolder, item[1])
            self.debug('{} → {}'.format(os.path.basename(localFilePath), item[1]))
            if not os.path.exists(os.path.dirname(localNewPath)):
                os.makedirs(os.path.dirname(localNewPath))
            shutil.copy(localFilePath, localNewPath)
            # Update modification-time of the file to speedup comparison on the next sync
            os.utime (localNewPath, (-1, item[0]))
            index += 1
        # Removing source-files
        for item in pathes:
            os.remove(item)
        # Merge lists
        localNew_l4 = []
        localNew_l4.extend(local_l4)
        localNew_l4.extend(diff_l4)
        localNew_l4.sort()
        # Store
        self.storeLocalLog(localNew_l4)
        ## Merge number 2: Update the remote repository
        self.debug('    Update the remote repository')
        # Get files to remove and add
        diff_l4 = self.createDiffFromDict(remote_dict, target_dict)
        if diff_l4: # If diff_l4 is not empty
            self.notify('      Updating {} files in the remote repository'.format(len(diff_l4)))
        queuePush_l4 = []
        for item in diff_l4:
            if item[3] == '-':
                #self.debug('  Remove from remote repository: {}'.format(item[1]))
                # Do nothing at the moment, removing files on the remote should only be done if self.cleanup is True
                pass
            elif item[3] == '+':    # Add to remote repository, push from remote
                queuePush_l4.append(item)
            else:
                print('      Well, erm, shit: {}'.format(item))
        # Create a dict of unique items to push
        queuePush_dict = {}
        for item in queuePush_l4:
            if not item[2] in queuePush_dict:
                queuePush_dict[item[2]] = item[1]
        len_dict = len(queuePush_dict)
        len_l4 = len(queuePush_l4)
        # Encrypt and push
        pathes = []
        index = 0
        for hashsum in queuePush_dict:
            self.debug(hashsum)
            localPath = self.encryptFile(queuePush_dict[hashsum], hashsum, self.getKey(hashsum))
            remotePath = os.path.join('files', hashsum)
            self.push(localPath, remotePath)
            os.remove(localPath)
        # Merge lists
        remoteNew_l4 = []
        remoteNew_l4.extend(local_l4)
        remoteNew_l4.extend(diff_l4)
        remoteNew_l4.sort()
        # Store
        serverLogPath = os.path.join(self.remotePath, 'remote.log')
        with self.sftp.open(serverLogPath, 'w') as fOut:
            data = json.dumps(remoteNew_l4)
            enc = self.gpg.encrypt(data, passphrase=self.masterKey, armor=True, encrypt=False, symmetric=True, cipher_algo=self.encryption, compress_algo='ZIP')
            enc = enc.data # Just the encrypted data, nothing else
            fOut.write(enc.decode('utf-8'))
        ## Sync keys
        # Get a list of all avaliable hashsums (files to keep)
        filesKeep_list = []
        for item in target_dict:
            if not target_dict[item]['hashsum'] in filesKeep_list:
                filesKeep_list.append(target_dict[item]['hashsum'])
        # Sync keys using this list
        self.syncKeysWithRemote(cleanup=self.cleanup, keys=filesKeep_list)
        ## Cleanup of the remote repository
        if self.cleanup:
            self.debug('  Cleaning up files on the remote repository…')
            # Get all files on remote
            filesAll_list = self.sftp.listdir(os.path.join(self.remotePath, 'files'))
            # Cleanup
            for hashsum in filesAll_list:
                if not hashsum in filesKeep_list:
                    self.debug('    Removing file: {}'.format(hashsum))
                    self.sftp.remove(os.path.join(self.remotePath, 'files', hashsum))
        # Unlock
        self.unlock()
        # Disconnect
        self.disconnect()
        # Done
        self.debug('Full sync done') #*knocks itself on her virtual shoulder*')
