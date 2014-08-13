#!/usr/bin/env python3
# -*- coding: utf-8 -*-


## Readme | http://cloudzec.org
#
# This is the basic CloudZec Class
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
# 0  - float  | Access-time of the file in UNIX-format, from os.path.getatime(path) or time.time() [previously used modification-time, os.path.getmtime(path), see bug #12)
# 1  - string | Relative path of file, e.g. folder/file1.txt
# 2  - string | Hashsum of file
# 3  - string | Action, can either be + or -
#
#
## local.keys and remote.keys | ecnrypted with masterKey
#
# {
#   "hashsum": ["encryption key", "filename on server"],
#   "hashsum": ["encryption key", "filename on server"],
#   "hashsum": ["encryption key", "filename on server"]
# }
#


## Imports
import errno
import getpass
import hashlib
import json
import os
import platform
import random
import shutil
import stat
import string
# External
import gnupg
import paramiko


## Class
class CloudZec:
    def __init__(self, genMasterKey=False, notifyCallback=None, debug=False):
        ## Basic setup
        self._debug = debug
        # Default pathes
        home = os.path.expanduser('~')
        self.confFolder = os.path.join(home, '.cloudzec')
        self.confFile = os.path.join(self.confFolder, 'cloudzec.conf')
        self.keysFile = os.path.join(self.confFolder, 'keys')
        self.localLog = os.path.join(self.confFolder, 'local.log')
        # Empty vars
        self.masterKey = None           # MasterKey
        self.keys      = {}             # Keys for data en/decryption
        # Default configuration, use loadConfiguration() to override
        self.cache = os.path.join(self.confFolder, 'cache')
        self.cleanup = True            # If True, everything that is no longer needed will be removed from both, local and remote (keys on both repositories and files on the remote)
        self.compression = 'none'       # Preferred compression algorithm |"none": Uncompressed (best for binary files) |"ZIP": Zip compression, PGP-compatible |"ZLIB": Zlib compression, incompatible to PGP |"BZIP2": Bzip2 compression, only compatible with GnuPG | Choose wisely
        self.device = platform.node()   # Device name, neccessary for lock-name on remote
        self.encryption = 'AES256'      # Preferred encryption algorithm
        self.hashAlgorithm = 'sha256'   # Preferred hash algorithm from hashlib:  md5, sha1, sha224, sha256, sha384, sha512
        self.identFile = None           # Identify file for remote login, None if password login is preferred over publickey authentication
        self.masterKeyFile = None       # None tries to find a keyring, else set a path like: os.path.join(self.confFolder, 'masterKey')
        self.remoteHost = 'cloudzec.org'    # Remote host
        self.remotePath = None          # CloudZec-folder on remote device
        self.remotePort = 22            # Remote port
        self.remoteUsername = None      # Username for remote login
        self.syncFolder = os.path.join(home, 'CloudZec')    # Local sync-folder
        self.syncKeys = True            # Sync keys with the remote host only if self.syncKeys is True
        self.useTimestamp = True        # If True, a timestamp comparison is done instead of generating hashsums. This speeds up a lot but is not as good as comparing hashsums
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
        # Check remoteUsername
        if self.remoteUsername is None:
            # Don't ask anything in __init__()
            raise Exception('You need to set a username in {}'.format(self.confFile))
        # Create gpg instance | needs to be defined before en/decrypting anything
        homedir = os.path.join(home, '.gnupg')
        if gnupg.__version__.startswith('1.2'): # The „new“ version of GnuPG from isislovecruft on GitHub
            binary = '/usr/bin/gpg2' # No symlinks allowed
            self.gpg = gnupg.GPG(binary=binary, homedir=homedir)
        else:   # „Old“ versions or other versions of GnuPG:
            self.gpg = gnupg.GPG(gnupghome=homedir)
            self.gpg.encoding = 'utf-8'
        ## Set empty rng (random number generator), needs to be done before loading master key
        self.rng = None
        ## Load master key | Needs to be done before storing something (encrypted)
        self.loadMasterKey(genMasterKey)
        ## Load keys
        self.loadKeys()
        # Rewrite?
        if rewrite:
            self.debug('Rewrite configuration')
            self.storeConfiguration()
        ## Set notify callback
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
        # If self.remotePath exists
        if self.remotePathExists():
            # Lock (because: why not?)
            self.lock()
            # Clear everything in self.remotePath
            self.remoteTreeRemove(self.remotePath)
        # Setup self.remotePath
        self.sftp.mkdir(self.remotePath)
        self.sftp.mkdir(os.path.join(self.remotePath, 'files'))
        # Unlock and disconnect (well, disconnect should fail)
        self.unlock()
        self.disconnect()


    def debug(self, text):
        """
        Prints debug text if self._debug is True

        @param text: Text to print
        @type text: str
        """
        if self._debug:
            print('{}'.format(text))


    def loadConfiguration(self):
        """
        Load configuration from self.confFile and set values (self.$variable)
        """
        self.debug('Load Configuration: {}'.format(self.confFile))
        conf = None
        with open(self.confFile, 'r') as fIn:
            conf = json.load(fIn)
        rewrite = False
        keys = ['cache', 'cleanup', 'compression', 'device', 'encryption', 'hashAlgorithm', 'identFile', 'masterKeyFile', 'remoteHost', 'remotePath', 'remotePort', 'remoteUsername', 'syncFolder', 'syncKeys', 'useTimestamp']
        for key in keys:
            try:
                exec('self.{} = conf[\'{}\']'.format(key, key))
            except KeyError as e:
                self.debug('  KeyError: {}'.format(e))
                rewrite = True
        # Check if compression is "none" ("none" breaks the output stream in python-gnupg from isislovecruft, v1.2.5)
        if self.compression == 'none':
            self.compression = 'Uncompressed'
            rewrite = True
        # And rewrite if necessary
        if rewrite:
            self.storeConfiguration()


    def storeConfiguration(self):
        """
        Store configuration into self.confFile (values read from self.$variable)
        """
        self.debug('Store Configuration: {}'.format(self.confFile))
        keys = ['cache', 'cleanup', 'compression', 'device', 'encryption', 'hashAlgorithm', 'identFile', 'masterKeyFile', 'remoteHost', 'remotePath', 'remotePort', 'remoteUsername', 'syncFolder', 'syncKeys', 'useTimestamp']
        conf = {}
        for key in keys:
            exec('conf[\'{}\'] = self.{}'.format(key, key))
        with open(self.confFile, 'w') as fOut:
                json.dump(conf, fOut, sort_keys=True, indent=2)


    def loadMasterKey(self, genMasterKey=False):
        """
        Load master key into self.masterKey, if genMasterKey is True and no key was found, key will be generated and self.storeMasterKey() is called

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
                print('  Using {} as fallback'.format(self.masterKeyFile))
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
        Store master key, either into a keyring or into self.masterKeyFile
        """
        # Hint: Run self.loadMasterKey() before this, otherwise it won't work (no keyring will be found)
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
                self.keys = json.load(fIn)
                # Check for upgrade from hashsum:key to hashsum:[key, filename]
                self.keys = self.upgradeKeys(self.keys)
        else:
            self.storeKeys()


    def storeKeys(self, keys=None):
        """
        Store self.keys into self.keysFile
        """
        self.debug('Store keys: {}'.format(self.keysFile))
        if keys is not None:
            self.keys = keys
        with open(self.keysFile, 'w') as fOut:
            json.dump(self.keys, fOut, sort_keys=True, indent=2)


    def upgradeKeys(self, dictKeys):
        """
        Upgrade from hashsum:key to hashsum:[key, filename]
        
        @param dictKeys: either a dict of keys using the old or the new format
        @type dictKeys: dict
        @return: Dict in the form of hashsum:[key, filename]
        """
        self.debug('Upgrading keys…')
        if dictKeys: # If dictKeys is not empty
            # Get a random item
            key = list(dictKeys.keys())[0]
            item = dictKeys[key]
            # And check if it is a string (old format) or a list (new format)
            if isinstance(item, list):
                return dictKeys
            elif isinstance(item, str):
                self.debug('  It\'s a str (old format), need to upgrade…')
                newDictKeys = {}
                for hashsum in dictKeys:
                    newDictKeys[hashsum] = [dictKeys[hashsum], hashsum]
                return newDictKeys
            else:
                raise Exception('Unknown type for keys: {}'.format(type(item)))
        else:
            return dictKeys


    def getKey(self, hashsum, generateKey=True):
        """
        Return key for en-/decryption based on the given hash

        @param hashsum: The key/hash-value
        @param hashsum: str
        @param generateKey: If True, a key will be generated if required. If False an exception will be thrown
        @param generateKey: bool
        @return: Returns a key for en-/decryption
        """
        self.debug('Get key: {}'.format(hashsum))
        if hashsum in self.keys:
            return self.keys[hashsum][0]
        else:
            if generateKey:
                self.keys[hashsum] = [self.genSymKey(), self.genFilename()] # If we don't have a key, we also don't have a flename
                self.storeKeys()
                return self.keys[hashsum][0]
            else:
                raise Exception('No key found for {}'.format(hashsum))


    def getFilename(self, hashsum):
        """
        Return filename for the remote host based on the given hash

        @param hashsum: The key/hash-value
        @param hashsum: str
        @return: Returns a filename for the remote host
        """
        #self.debug('Get filename: {}'.format(hashsum))
        if hashsum in self.keys:
            if self.keys[hashsum][1] is None:
                #self.keys[hashsum][1] = self.genFilename()
                #self.storeKeys() # We need to store the keys, otherwise CloudZec will forget it
                raise Exception('We don\'t have a filename but a key? The fuck is wrong with you?')
            return self.keys[hashsum][1]
        else:
            raise Exception('Hashsum is not in self.keys, this should not happen :(')
    
    
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


    def genFilename(self, length=32):
        """
        Generates a nice filename

        @param length: Length of filename
        @type length: int
        @return: Returns a filename
        """
        self.debug('Generate filename')
        # Generate a random string
        chars = string.ascii_letters + string.digits
        filenames = set( item[1] for item in self.keys )
        filename = None
        while filename is None or filename in filenames:
            filename = ''.join(random.choice(chars) for i in range(length))
        return filename
 

    def loadLocalLog(self):
        """
        Loads local log from self.localLog and returns it

        @return: Returns list in l4 format
        """
        self.debug('Load local log: {}'.format(self.localLog))
        local = []
        if os.path.exists(self.localLog):
            with open(self.localLog, 'r') as fIn:
                data = fIn.read()
                local = json.loads(data)
        local.sort()
        return local


    def storeLocalLog(self, log):
        """
        Stores local log into self.localLog

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
        self._transport = paramiko.Transport((self.remoteHost, self.remotePort))
        self.sftp = None
        if self.identFile is None:
            self.debug('  Use password login')
            try:
                self._transport.connect(username=self.remoteUsername, password=getpass.getpass('    Password for remote host: '))
            except paramiko.ssh_exception.BadAuthenticationType:
                self.debug('      Hm. Login with password doesn\'t work. Did you set „identFile“ in {}?'.format(self.confFile))
                raise Exception('Remote host doesn\'t accept passwords')
        else:
            self.debug('  Use identity file for login')
            key = None
            identFile = os.path.expanduser(self.identFile)
            try:
                key = paramiko.RSAKey.from_private_key_file(identFile)
            except paramiko.ssh_exception.PasswordRequiredException:
                key = paramiko.RSAKey.from_private_key_file(identFile, password=getpass.getpass('    Password for identity file: '))
            self._transport.connect(username=self.remoteUsername, pkey=key)
        self.sftp = paramiko.SFTPClient.from_transport(self._transport)
        self.debug('  Connected to remote host: {}@{}:{}'.format(self.remoteUsername, self.remoteHost, self.remotePort))
        # Check remotePath | Path like /home/$remoteUsername/cloudzec on the remote device!
        if self.remotePath is None:
            self.debug('  Create default remotePath')
            self.remotePath = os.path.join(self.sftp.normalize('.'), 'cloudzec')
            self.debug('    {}'.format(self.remotePath))
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
            if isinstance(data, str):
                name = json.loads(data)
            elif isinstance(data, bytes):
                data = data.decode('utf-8')
                name = json.loads(data)
            else:
                raise TypeError('Neither a string nor a byte array: {}'.format(type(data)))
        return name


    def lock(self):
        """
        Try to lock remote directory, raises exception if remote host can't be locked
        """
        self.debug('Lock remote directory')
        self.sftp.chdir(self.remotePath)
        if 'lock' in self.sftp.listdir(self.remotePath):
            name = self.getLockName()
            if self.device == name:
                self.debug('  Already locked (from this device)')
            else:
                self.debug('  Already locked (from {})'.format(name))
                self.disconnect()
                raise Exception('Cannot lock remote directory (locked by {})'.format(name))
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
                    raise Exception('Could not unlock remote directory')
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
        for item in l4:
            if item[3] == '+':
                timestamp = item[0]
                relativePath = item[1]
                hashsum = item[2]
                d[relativePath] = {'timestamp':timestamp, 'hashsum':hashsum}
            elif item[3] == '-':
                relativePath = item[1]
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
            if os.path.islink(filename):    # Caution: os.path.isfile() returns True if the linked item is a file! So check first, if it is a link!
                self.debug('  Ignoring link: {}'.format(filename))
            else:
                timestamp = os.path.getatime(filename)
                relativePath = filename.split(self.syncFolder)[1][1:]
                hashsum = None
                if relativePath in compareDict and self.useTimestamp: # is True
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
        # Sort and return
        l4.sort()
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
        self.sftp.get(remotePathAbs, localPath, callback=self.callbackTransferStatus)
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
        self.sftp.put(localPath, remotePathAbs, callback=self.callbackTransferStatus, confirm=True)


    def callbackTransferStatus(self, bytesT, bytesA):
        try:
            self.debug('  Transfer: {} of {} Bytes ({:.2f} %)'.format(bytesT, bytesA, bytesT/bytesA*100))
        except ZeroDivisionError as e:
            self.debug('Division by zero: {}/{}'.format(bytesT, bytesA))
            raise ZeroDivisionError('A ZeroDivisionError occured. This is not normal and most of the time when this error occurs, the encryption of a file using gpg failed, resulting in an empty file and is now causing a ZeroDivisionError. Seriously, check your files, your config and try it again!')


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
            binary = None
            if gnupg.__version__.startswith('1.2'): # The „new“ version of GnuPG from isislovecruft on GitHu
                binary = self.gpg.encrypt(fIn.read(), passphrase=passphrase, armor=False, encrypt=False, symmetric=True, always_trust=True, cipher_algo='AES256', compress_algo=self.compression)
            else:   # „Old“ versions or other versions of GnuPG:
                binary = self.gpg.encrypt(fIn.read(), passphrase=passphrase, armor=False, symmetric=True, always_trust=True, recipients=None)
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


    def syncKeysWithBoth(self, cleanup=False, keys=None):
        """
        Synchronises keys with remote if self.syncKeys is True, also stores the merged list of keys on the local repository using self.storeKeys()
        If cleanup is True, all keys that are no longer needed will be removed (using the list of hashsum/keys as reference)

        @param cleanup: If True only required keys are stored
        @type cleanup: bool
        @param keys: A list of hashsums/keys/whatever to keep
        @param keys: list
        """
        if self.syncKeys: # is True
            self.debug('Sync keys')
            # Open remote.keys
            remoteKeys = {}
            if self.remotePathExists('remote.keys'):
                remoteKeysPath = self.pull('remote.keys')
                localKeysPath = self.decryptFile(remoteKeysPath, passphrase=self.masterKey)
                with open(localKeysPath, 'r') as fIn:
                    remoteKeys = json.load(fIn)
                    # Check for upgrade from hashsum:key to hashsum:[key, filename]
                    remoteKeys = self.upgradeKeys(remoteKeys)
                # Remove tmpfile
                os.remove(localKeysPath)
            # Merge with local keys
            targetKeys = {}
            for key in self.keys:
                targetKeys[key] = self.keys[key]
            for key in remoteKeys:
                if key in targetKeys:
                    if targetKeys[key][0] == remoteKeys[key][0]:
                        pass
                    else:
                        print('Damnit, Keys don\'t match for {}'.format(key))
                    if targetKeys[key][1] == remoteKeys[key][1]:
                        pass
                    else:
                        print('Damnit, Filenames don\'t match for {}'.format(key))
                else:
                    targetKeys[key] = remoteKeys[key]
            # Cleanup if cleanup is True and keys is not None
            if keys is not None and cleanup: # is True
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
            if not targetKeys == self.keys:     # Only compares the keys but its okay this time because we checked the values already a few lines above
                self.storeKeys(targetKeys)
            # And remote
            if not targetKeys == remoteKeys:    # Only compares the keys but its okay this time because we checked the values already a few lines above
                serverLogPath = os.path.join(self.remotePath, 'remote.keys')
                with self.sftp.open(serverLogPath, 'w') as fOut:
                    data = json.dumps(targetKeys)
                    enc = None
                    if gnupg.__version__.startswith('1.2'): # The „new“ version of GnuPG from isislovecruft on GitHub
                        enc = self.gpg.encrypt(data, passphrase=self.masterKey, armor=True, encrypt=False, symmetric=True, cipher_algo=self.encryption, compress_algo='ZIP')
                    else:   # „Old“ versions or other versions of GnuPG:
                        enc = self.gpg.encrypt(data, passphrase=self.masterKey, armor=True, symmetric=True, recipients=None)
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
        # Sort and return
        diff_l4.sort()
        return diff_l4


    def loadRemoteLog(self):
        """
        Loads remote.log and returns it

        @return: Returns list in l4 format
        """
        self.debug('Load remote log…')
        remote = []
        if self.remotePathExists('remote.log'):
            remote = []
            # Pull remote.log and decrypt it
            remoteLogPath = self.pull('remote.log')
            localLogPath = self.decryptFile(remoteLogPath, passphrase=self.masterKey)
            # Read it
            with open(localLogPath, 'r') as fIn:
                remote = json.load(fIn)
            # Remove tmpfile
            os.remove(localLogPath)
        # Sort and remote
        remote.sort()
        return remote


    def storeRemoteLog(self, log):
        """
        Stores remote log

        @param log: list in l4 format
        @type log: list
        """
        self.debug('Store remote log…')
        log.sort()
        remoteLogPath = os.path.join(self.remotePath, 'remote.log')
        with self.sftp.open(remoteLogPath, 'w') as fOut:
            data = json.dumps(log)
            enc = None
            if gnupg.__version__.startswith('1.2'): # The „new“ version of GnuPG from isislovecruft on GitHub
                enc = self.gpg.encrypt(data, passphrase=self.masterKey, armor=True, encrypt=False, symmetric=True, cipher_algo=self.encryption, compress_algo='ZIP')
            else:   # „Old“ versions or other versions of GnuPG:
                enc = self.gpg.encrypt(data, passphrase=self.masterKey, armor=True, symmetric=True, recipients=None)
            enc = enc.data # Just the encrypted data, nothing else
            fOut.write(enc.decode('utf-8'))


    def sync(self):
        """
        Full sync between local and remote repository, version 2 using a queue and notifcations
        """
        self.debug('Full sync')
        self.notify('Starting full sync…')
        ## Real files -> Local files
        self.debug('  Syncing real files and local files')
        # Load local.log
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
        # Connect and lock
        self.connect()
        self.lock()
        # Load remote.log
        remote_l4 = self.loadRemoteLog()
        # Load local.log
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
        ## Sync keys before syncing files, otherwise decryption with files from remote to local will throw an exception, don't cleanup keys
        self.syncKeysWithBoth()
        ## Merge number 1: Update the local repository
        self.debug('  Update the local repository')
        # Get files to remove and add
        diff_l4 = self.createDiffFromDict(local_dict, target_dict)
        if diff_l4: # If diff_l4 is not empty
            if len(diff_l4) == 1:
                self.notify('Updating 1 file in the local repository')
            else:
                self.notify('Updating {} files in the local repository'.format(len(diff_l4)))
        queuePull_l4 = []
        for item in diff_l4:
            if item[3] == '+':      # Add to local repository, pull from remote
                queuePull_l4.append(item)
            elif item[3] == '-':    # Remove from local repository
                self.debug('      Remove from local repository: {}'.format(item[1]))
                localFilePath = os.path.join(self.syncFolder, item[1])
                os.remove(localFilePath)
                # Remove emtpy folder if self.cleanup is True
                if self.cleanup: # is True
                    self.debug('      Cleaning up empty directories…')
                    relativePath = os.path.dirname(item[1])
                    while True:
                        absolutePath = os.path.join(self.syncFolder, relativePath)
                        if os.listdir(absolutePath):    # If a list contains items, its boolean value is True
                            break
                        else:   # If the list is empty (== empty directory)
                            self.debug('        Removing folder {}'.format(absolutePath))
                            os.rmdir(absolutePath)
                            relativePath = os.path.dirname(relativePath)
                            # Check if we already hit the top folder within self.confFolder
                            if relativePath == os.path.dirname(relativePath):
                                break
            else:
                print('Well, erm, shit: {}'.format(item))
        # Create a set (of unique items) to pull
        queuePull_set = set( item[2] for item in queuePull_l4 )
        # Pull and decrypt
        pathes = []
        for hashsum in queuePull_set:
            remoteFilePath = self.pull(os.path.join('files', self.getFilename(hashsum)))
            localFilePath = self.decryptFile(remoteFilePath, passphrase=self.getKey(hashsum, generateKey=False))
            pathes.append(localFilePath)
        # Copying
        for item in queuePull_l4:
            localFilePath = os.path.join(self.cache, self.getFilename(item[2]))
            localNewPath = os.path.join(self.syncFolder, item[1])
            self.debug('{} → {}'.format(os.path.basename(localFilePath), item[1]))
            if not os.path.exists(os.path.dirname(localNewPath)):
                os.makedirs(os.path.dirname(localNewPath))
            shutil.copy(localFilePath, localNewPath)
            # Update access and modification-time of the file to speedup comparison on the next sync
            os.utime(localNewPath, (item[0], item[0]))
        # Removing source-files
        for item in pathes:
            os.remove(item)
        # Store remote log. Do not merge the remote_l4 and the diff_l4, just store the target_l4. If the remote log got removed, you would only store the diff and this is not enough. Only the target_l4 contains the whole history
        self.storeLocalLog(target_l4)
        ## Merge number 2: Update the remote repository
        self.debug('  Update the remote repository')
        # Get files to remove and add
        diff_l4 = self.createDiffFromDict(remote_dict, target_dict)
        if diff_l4: # If diff_l4 is not empty
            if len(diff_l4) == 1:
                self.notify('Updating 1 file in the remote repository')
            else:
                self.notify('Updating {} files in the remote repository'.format(len(diff_l4)))
        queuePush_l4 = []
        for item in diff_l4:
            if item[3] == '+':      # Add to remote repository, push from local to remote
                queuePush_l4.append(item)
            elif item[3] == '-':
                # Do nothing, removing files on the remote repository is done later in a more efficient way
                pass
            else:
                print('Well, erm, shit: {}'.format(item))
        # Create a dict of unique items to push
        queuePush_dict = {}
        for item in queuePush_l4:
            if not item[2] in queuePush_dict:
                queuePush_dict[item[2]] = item[1]
        # Encrypt and push
        for hashsum in queuePush_dict:
            self.debug(hashsum)
            localPath = self.encryptFile(queuePush_dict[hashsum], hashsum, self.getKey(hashsum))
            remotePath = os.path.join('files', self.getFilename(hashsum))
            self.push(localPath, remotePath)
            os.remove(localPath)
        # Store remote log. Do not merge the remote_l4 and the diff_l4, just store the target_l4. If the remote log got removed, you would only store the diff and this is not enough. Only the target_l4 contains the whole history
        self.storeRemoteLog(target_l4)
        ## Cleanup and sync keys
        # Get a set of all avaliable hashsums (files) to keep
        hashsumsKeep_set = set( target_dict[item]['hashsum'] for item in target_dict )
        # Sync keys using this list
        self.syncKeysWithBoth(cleanup=self.cleanup, keys=hashsumsKeep_set)
        # Cleanup of the remote repository
        if self.cleanup:
            self.debug('  Cleaning up files on the remote repository…')
            # Get all files on remote
            filesAll_list = self.sftp.listdir(os.path.join(self.remotePath, 'files'))
            # Get all filenames to keep
            filesKeep_set = set()
            for hashsum in hashsumsKeep_set:
                filesKeep_set.add(self.getFilename(hashsum))
            # Cleanup
            for filename in filesAll_list:
                if not filename in filesKeep_set:
                    self.debug('    Removing file {}'.format(filename))
                    self.sftp.remove(os.path.join(self.remotePath, 'files', filename))
        # Unlock and disconnect
        self.unlock()
        self.disconnect()
        # Done
        self.notify('Full sync done')
        self.debug('Full sync done') #*knocks itself on her virtual shoulder*')
