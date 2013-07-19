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
## Compression | TarFile
#  http://docs.python.org/3.3/library/tarfile.html
#  http://docs.python.org/3.3/library/archiving.html
#
#
## GnuPG | python-gnupg fork | Fast development, including security patches, etc.
#  https://github.com/isislovecruft/python-gnupg/
#
## GnuPG | python-gnupg | very slow development, security patches?
#  http://code.google.com/p/python-gnupg/
#  http://pythonhosted.org/python-gnupg/
#  https://github.com/revogit/python-gnupg
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
## Inotify | python-pyinotify
#  https://github.com/seb-m/pyinotify
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
## alloc.conf | Every file is packaged and compressed, so user rights, name, path, etc. can be restored (uri is still needed for syncToServer() in removing an item)
#  {
#    "hash1":("key1", "folder/file1"),
#    "hash2":("key2", "folder/file2"),
#    "hash3":("key3", "folder/file3"),
#    "hash4":("key4", "folder/file4"),
#    "hash5":("key5", "folder/file5"),
#    "hash6":("key6", "folder/file6"),
#    "hash7":("key7", "folder/file7"),
#    "hash8":("key8", "folder/file8"),
#    "hash9":("key9", "folder/file9")
# }
#
## history
# +123456789.sha256     # File added
# +123789456.sha256     # File added
# -123456789.sha256     # File removed
# ?123789456.sha256 789456123.sha256    # First file gets replaced by second file
#


## Imports
import os
import json
import shutil
import string
import random # Not safe for key generation!
import getpass
import hashlib
import tarfile
import platform
import subprocess
#
import gnupg
import paramiko


## Classes
class CloudZec:
    def __init__(self, name=platform.node(), username=None, identFile=None, host='cloudzec.org', port=22, fingerprint=None, serverpath=None, genMasterKey=True, ask=None, askPassword=None, debug=False):
        """
        @param name: Alias for this device
        @type name: str
        @param username: Username for server login
        @type username: str
        @param identFile: None or path to your ssh key, None means password login, a path means identity file, path can be relative: ~/.ssh/id_rsa
        @type identFile: str or NoneType
        @param host=: Server (Domain or IP)
        @type host: str
        @param port: Serverport
        @type port: int
        @param fingerprint: 8-digit fingerprint of gpg key pair
        @type fingerprint: str
        @param serverpath: Path on server to sync from/to
        @type serverpath: str
        @param genMasterKey: If true and key file is missing a masterkey will automatically be generated
        @type genMasterKey: bool
        @param ask: Alternative function to ask for something (name, username, fingerprint, etc)
        @type ask: function
        @param askPassword: Alternative function to ask for gpg private key passwords
        @type askPassword: function
        @param debug: Print debug output
        @type debug: bool
        """
        ## Alternative functions
        if not ask is None:
            self.ask = ask
        if not askPassword is None:
            self._askPassword = askPassword
        ## Data/Basic setup
        home = os.path.expanduser('~')
        self.confFolder = os.path.join(home, '.cloudzec')
        self.confFile = os.path.join(self.confFolder, 'cloudzec.conf')
        self._debug = debug
        self.conf = None
        self.defaultConf = {'name'        : name,
                            'username'    : username,
                            'identityFile': identFile,
                            'host'        : host,
                            'port'        : port,
                            'cache'       : os.path.join(self.confFolder, 'cache'),
                            'cacheUp'     : os.path.join(self.confFolder, 'cache', 'upload'),
                            'cacheDown'   : os.path.join(self.confFolder, 'cache', 'download'),
                            'history'     : os.path.join(self.confFolder, 'history.log'),# Local history
                            'allocation'  : os.path.join(self.confFolder, 'alloc.conf'), # Allocation of files, JSON format
                            'fingerprint' : fingerprint,                                 # Fingerprint of gpg keys
                            'syncfolder'  : os.path.join(home, 'CloudZec'),              # Local sync-folder
                            'serverpath'  : serverpath,                                  # Path on server, default shoul be something like /home/<username>/cloudzec
                            'allocSync'   : True,                                        # If true, allocation will be synced
                            'masterKey'   : os.path.join(self.confFolder, 'key'),        # Masterkey for alloc.conf en-/decryption
                            'compression' : 'bzip2', # Preferred compression algorithm |lzma: slow compress, small file, very fast decompress |bzip2: fast compress, small file, fast decompress |gzip: big file, very fast compress, very fast decompress |Choose wisely
                            'encryption'  : 'aes256' # Preferred encryption algorithm
                           }
        self.gpg = gnupg.GPG()
        #self.gpg.encoding = 'utf-8'
        ## Check conf
        # Create confFolder if missing
        if not os.path.exists(self.confFolder):
            os.makedirs(self.confFolder)
            self.debug('Create confFolder {}'.format(self.confFolder))
        # Create confFile if missing
        if not os.path.exists(self.confFile):
            self.writeConf(self.confFile, self.defaultConf)
            self.debug('Create confFile {}'.format(self.confFile))
        # Read and check confFile
        with open(self.confFile, 'r') as f:
            self.conf = json.load(f)
            rewrite = False
            # Missing keys
            for key in self.defaultConf:
                if not key in self.conf:
                    rewrite = True
                    self.conf[key] = self.defaultConf[key]
                    self.debug('Add missing key: {}\t ({})'.format(key, self.defaultConf[key]))
            # Unnecessary keys
            tmpConf = self.conf.copy()
            for key in tmpConf:
                if not key in self.defaultConf:
                    rewrite = True
                    del self.conf[key]
                    self.debug('Remove unnecessary key: {}'.format(key))
            # Rewrite if needed
            if rewrite:
                self.writeConf(self.confFile, self.conf)
                self.debug('Rewrite conf')
        ## Check files and folders in config
        # Check folder: cacheUp
        if not os.path.exists(self.conf['cacheUp']):
            os.makedirs(self.conf['cacheUp'])
            self.debug('Create folder: {}'.format(self.conf['cacheUp']))
        # Check folder: cacheDown
        if not os.path.exists(self.conf['cacheDown']):
            os.makedirs(self.conf['cacheDown'])
            self.debug('Create folder: {}'.format(self.conf['cacheDown']))
        # Check folder: syncfolder
        if not os.path.exists(self.conf['syncfolder']):
            os.makedirs(self.conf['syncfolder'])
            self.debug('Create folder: {}'.format(self.conf['syncfolder']))
        # Check username, serverpath and fingerprint
        rewrite = False
        # username
        if self.conf['username'] is None:
            self.conf['username'] = self.ask('Username for server login: ', 'str')
            rewrite = True
        # serverpath | path like /home/$username/cloudzec on the server!
        if self.conf['serverpath'] is None:
            self.conf['serverpath'] = os.path.join('/home', self.conf['username'], 'cloudzec')
            #raise Exception('serverpath')
            rewrite = True
        # fingerprint
        if not self.validKey():
            #raise Exception('No valid key/fingerprint of gpg key')
            self.conf['fingerprint'] = self.ask('Fingerprint (last 8 digits) of gpg key pair to use: ', 'str')
            rewrite = True
        # Rewrite if needed
        if rewrite:
            self.writeConf(self.confFile, self.conf)
            self.debug('Rewrite conf')
        # Check history, create empty file if not present
        if not os.path.exists(self.conf['history']):
            with open(self.conf['history'], 'w') as f:
                f.write('')
            self.debug('Create empty history')
        # Check allocation, create empty file if not present
        if not os.path.exists(self.conf['allocation']):
            self.writeConf(self.conf['allocation'], {})
            self.debug('Create empty allocation')
        # Get master key
        self.masterkey = self.getMasterKey(genMasterKey)


    def getMasterKey(self, genMasterKey=False):
        """
        Returns master key. Master key may be encrypted or stored in a keyring (if you want to store it in a keyring, overwrite this)

        @return: master key as string
        """
        if not os.path.exists(self.conf['masterKey']):
            self.debug('There is no master en-/decyption key present.')
            if genMasterKey:
                return self.setMasterKey(self.genSymKey())
            else:
                raise Exception('No master key present. Quit.')
        else:
            pass #TODO


    def setMasterKey(self, key):
        """
        Stores master key, should be overwritten if you want to store it in a keyring or something like that
        """
        keyEncrypted = str(self.gpg.encrypt(key, self.conf['fingerprint']))
        with open(self.conf['key'], 'w') as f:
            f.write(keyEncrypted)


    def debug(self, text):
        """
        Prints debug text if self._debug is True

        @param text: Text to print
        @type text: str
        """
        if self._debug:
            print('Debug: {}'.format(text))


    def writeConf(self, foutAbs, conf):
        """
        Writes nicely formatted configuration-file

        @param foutAbs: Absolute filepath to store
        @type foutAbs: str
        @param conf: Dictionary to store
        @type conf: dict
        """
        with open(foutAbs, 'w') as f:
            f.write(json.dumps(conf, indent=2, sort_keys=True))
            if self._debug:
                self.debug('Write configuration file: {}'.format(foutAbs))


    def validKey(self):
        """
        Checks if fingerprint is valid (in GPG keystore)

        @return: Returns True if fingerprint was found
        """
        fingerprints = []
        for key in self.gpg.list_keys():
            fingerprints.append(key['keyid'][-8:])
        if self.conf['fingerprint'] in fingerprints:
            return True
        return False


    def genSymKey(self, length=32):
        """
        Generates nice symmetric key

        @param length: Length of symmetric key
        @type length: int
        @return: Returns a safe random key
        """
        # TODO: This is not fucking safe! (But still better than no key)
        chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(chars) for i in range(length))


    def ask(self, question, returntype):
        """
        This should be overwritten. Whenever a variable is needed, this function will be called.

        @param question: Question for default command line interface
        @type question: str
        @param returntype: Type of return, should not be ignored!
        @type returntype: str
        @return: Returns for whatever has been asked for
        """
        if returntype is 'str':  # Just ask the question and return the result
            return input(question)
        elif returntype is 'bool': # Yes/No, Yes is True, No is False
            print(question)
            result = None
            while not result in ('yes', 'y', 'no', 'n'):
                result = input('[Y]es or [N]o? ').lower()
            if result.startswith('y'):
                return True
                return False
        else: # Fallback
            return input(question)


    def askFingerprintPassword(self, fingerprint=None):
        """
        Asks for fingerprint password (not directly, calls _askPassword for this which can/should be overwritten).

        @param fingerprint: Fingerprint of gpg private key that will be decrypted
        @type fingerprint: str
        @return Returns password for the gpg private key
        """
        if fingerprint is None:
            fingerprint = self.conf['fingerprint']
        return self._askPassword('Password for {}: '.format(fingerprint))


    def askPassword(self, question=None):
        """
        Asks for a password (not directly, calls _askPassword for this which can/should be overwritten).

        @param question: Question that will be asked
        @type question: str
        @return Returns the password for whatever
        """
        return self._askPassword(question)


    def _askPassword(self, text):
        """
        This should be overwritten. Whenever the password of a gpg private key is needed, this function will be called.

        @param text: Question that will be asked
        @type text: str
        @return Returns the password for whatever
        """
        return getpass.getpass(text)


    def sync(self):
        """
        Synchronizes with the server (full-sync)
        """
        self.debug('Sync')
        # Load allocation
        self.loadClientAllocation()
        # Connect
        self.connect()
        # Pull latest updates from server
        self.syncFromServer(disconnect=False) # Hold connection open, do not disconnect!
        # Push latest updates to the server
        self.syncToServer()
        # Disconnect
        self.disconnect() # we don't need to disconnect, syncToServer() does this for us
        # Store allocation
        self.storeClientAllocation()


    def syncFromServer(self, disconnect=True):
        """
        Pull the latest updates from server and merge with local folder

        @param disconnect: If false, connection stays open
        @type disconnect: bool
        """
        self.debug('SyncFromServer')
        # Connect
        self.connect()
        # Download server history and get local history
        historyServer = self.getServerHistory()
        historyClient = self.getClientHistory()
        # Get diff to local version
        historyDiff = self.getHistoryDiff(historyClient, historyServer)
        # First we only download all new things, removing, extraction, etc is done later
        for item in historyDiff:
            if item.startswith('+'):
                self.debug('Downloading... {}'.format(item[1:]))
                remote = os.path.join(self.conf['serverpath'], 'files', item[1:])
                local = os.path.join(self.conf['cacheDown'], item[1:])
                localPart = '{}.part'.format(local)
                self.sftp.get(remote, localPart)    # Download to a .part file
                shutil.move(localPart, local)   # Move when download is finished
                self.debug('  Done')
            elif item.startswith('?'):
                old, new = item.split(' ')
                self.debug('Downloading... {}'.format(new))
                remote = os.path.join(self.conf['serverpath'], 'files', new)
                local = os.path.join(self.conf['cacheDown'], new)
                localPart = '{}.part'.format(local)
                self.sftp.get(remote, localPart)    # Download to a .part file
                shutil.move(localPart, local)   # Move when download is finished
                self.debug('  Done')
        # Download alloc.conf if possible and write into local alloc.conf
        if 'alloc.conf' in self.sftp.listdir(self.conf['serverpath']):
            allocServer = None
            with self.sftp.open(os.path.join(self.conf['serverpath'], 'alloc.conf'), 'r') as f:
                data = f.read().decode('utf-8') # TODO: Do this right! As i heard, decode should not be used in cases like this. Maybe there are smarter ways
                allocServer = json.loads(data)
            allocClient = None
            with open(self.conf['allocation'], 'r') as f:
                allocClient = json.loads(f.read())
            for key in allocServer:
                if not key in allocClient:
                    allocClient[key] = allocServer[key]
            self.writeConf(self.conf['allocation'], allocClient)
        # Disconnect
        if disconnect:
            self.disconnect()
        # Apply changes, decrypt files, update history, decompress, etc
        for item in historyDiff:
            if item.startswith('-'):
                # Get URI
                uri = self.getURI(item[1:])
                if uri is not None:
                    # Remove
                    os.remove(os.path.join(self.conf['syncfolder'], uri))
                    # Add item to local history
                    self.addHistory(item)
            elif item.startswith('+'):
                # Decrypt
                path = os.path.join(self.conf['cacheDown'], item[1:])
                self.decrypt(path, path, item[1:])
                # Decompress and move
                self.decompress(item[1:])
                # Remove archive
                os.remove(os.path.join(self.conf['cacheDown'], item[1:]))
                # Add item to local history
                self.addHistory(item)
            #elif item.startswith('?'):
            #    # Decrypt
            #
            #    # Decompress and overwrite
            #    self.decompress)
            #    # Remove archive
            #    os.remove(os.path.join(self.conf['cacheDown'], ...)
            #    # Add item to local history
            #    self.addHistory(item)
            else:
                raise Exception('What. The. Fuck. {}'.format(item))


    def syncToServer(self, disconnect=True):
        """
        Push the latest updates to the server

        @param disconnect: If false, connection stays open
        @type disconnect: bool
        """
        self.debug('SyncToServer')
        # Get local history and the files still present (as history)
        historyClient = self.getClientHistory()
        historyChanges, uris = self.getClientChanges()
        # Get diff to local history
        historyDiff = self.getHistoryDiff(historyChanges, historyClient)
        print(historyDiff)
        # For every item in history diff
        for item in historyDiff:
            #if uri is not None:
            if item.startswith('-'):
                # Get uri
                uri = self.getURI(item[1:])
                # Remove file
                os.remove(os.path.join(self.conf['syncfolder'], uri))
                # Add item to local history
                self.addHistory(item)
            elif item.startswith('+'):
                # Get uri
                uri = uris[item[1:]]
                # Compress file
                self.compress(uri)
                # Encrypt file
                path = os.path.join(self.conf['cacheUp'], item[1:])
                self.encrypt(path, path, item[1:])
                # Update history
                self.addHistory(item)
            elif item.startswith('?'):
                # This won't happen.
                raise Exception('This should not happen, seems like your diff contains a new, experimental feature :)')
            else:
                raise Exception('What. The. Fuck. {}'.format(item))
            #else:
            #    raise Exception('What. The. Fuck. {}'.format(item))
        # Connect
        self.connect()
        # Lock
        self.lock()
        # Update server history
        history = self.getServerHistory()
        for item in historyDiff:
            history.append(item)
        # Upload new server history
        with self.sftp.open(os.path.join(self.conf['serverpath'], 'history.log'), 'w') as f:
            for item in history:
                f.write('{}\n'.format(item))
        # Upload/(Re)move files
        for item in historyDiff:
            self.debug('Uploading... {}'.format(item[1:]))
            local = os.path.join(self.conf['cacheUp'], item[1:])
            remote = os.path.join(self.conf['serverpath'], 'files', item[1:])
            self.sftp.put(local, remote)
            os.remove(local)    # Remove source file
            self.debug('  Done')
        # Unlock
        self.unlock()
        # Disconnect
        if disconnect:
            self.disconnect()


    #def getUri(self, hashsum):
    #    """
    #    Returns the uri of hash (read from $allocation)
    #
    #    @param hashsum: Hashsum of file
    #    @type hashsum: str
    #    @return: Relative uri of file or None if not found
    #    """
    #    uri = None
    #    with open(self.conf['allocation'], 'r') as f:
    #        data = json.loads(f.read())
    #        uri = data.get(hashsum)[1]
    #    return uri


    #def addHistory(self, item):
    #    """
    #    Adds $item to the local history
    #
    #    @param item: History-entry (like „+123456789.sha256“)
    #    @type item: str
    #    """
    #    history = self.getClientHistory()
    #    ## Experimental history cleanup for debuging ##
    #    files = self.getFiles(history)
    #    history = []
    #    for item in files:
    #        history.append('+{}'.format(item))
    #    ## Experimental history cleanup for debuging ##
    #    history.append(item)
    #    with open(self.conf['history'], 'w') as f:
    #        for item in history:
    #            f.write('{}\n'.format(item))


    def getServerHistory(self):
        """
        Pulls the server history and splits it into a list

        @return: History of the server
        """
        data = None #''
        with self.sftp.open(os.path.join(self.conf['serverpath'], 'history.log'), 'r') as f:
            #data = str(f.read()) # Does not work as expected
            data = f.read().decode('utf-8') # TODO: Do this right! As i heard, decode should not be used in cases like this. Maybe there are smarter ways
        # Decrypt data
        raise Exception('Data needs to be decrypted!')
        history = data.split('\n')
        while '' in history:
            history.remove('')
        return history


    def addServerHistory(self, item):
        pass


    def getClientHistory(self):
        """
        Gets the local history (from the file history.log) and splits it into a list

        @return: History of the local directory
        """
        data = None #''
        with open(self.conf['history'], 'r') as f:
            data = f.read()
        # Decrypt data
        raise Exception('Data needs to be decrypted!')
        history = data.split('\n')
        while '' in history:
            history.remove('')
        return history


    def addClientHistory(self, item):
        pass


    def getClientChanges(self):
        """
        Returns a list with history and a dict(hash:uri)

        @return: History of the local changes,dict(hash:uri)
        """
        history = []
        uris = {}
        #for root, dirs, files in os.walk(self.conf['syncfolder']):
        #   #    for item in files:
        #    #   path = item #os.path.join(root, item)
        #        hash = self.getHash(path)
        #        fileDict[path] = hash
        pathes = self.getFiles(self.conf['syncfolder'])
        for path in pathes:
            hashsum = self.getFilesFromPath(path)
            history.append('+{}'.format(hashsum))
            relPath = path.replace(self.conf['syncfolder'], '', 1)
            uris[hashsum] = relPath
        return history, uris


    def getFilesFromPath(self, path):
        """
        Returns a list of all files in path (including files in subdirecotries)

        @return: List of files
        """
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


    def getHistoryDiff(self, history1, history2):
        """
        Return the diff of two history-lists.
        There is no real prior history, but in the case of cases:
         - adding a file is prior to removing a file (well, should be)
         - history1 is prior to history2 (so, history1 is the „new“ history, history2 should be the „old“ history)

        @param history1: First history (should be newer)
        @type history1: list
        @param history2: Second history (should be older)
        @type history2: list
        @return: A history of the differences
        """
        # TODO: Make a better, a true diff (because here we don't get a real diff)
        diff = []
        # Get a list of all files in (history1, history2)
        files1 = self.getFiles(history1)
        files2 = self.getFiles(history2)
        ## First remove, then add (makes sure at the end there are more files than with first add, the remove, believe me)
        ## If file is in 2 and not in 1:
        for item in files2:
            if not item in files1:
                diff.append('-{}'.format(item))
        # If file is in 1 and not in 2:
        for item in files1:
            if not item in files2:
                diff.append('+{}'.format(item))
        # Return
        return diff


    def getFilesFromHistory(self, history, ignoreFaults=True):
        """
        Return a list of all files that should still be present (parses the history and returns all leftover files)

        @param history: A history
        @type history: list
        @param ignoreFaults: If true, errors in history are ignored. If false, an exception is raised
        @type ignoreFaults: bool
        @return: list
        """
        files = []
        for item in history:
            item = str(item)
            if item.startswith('+'):
                if not item[1:] in files:
                    files.append(item[1:])
            elif item.startswith('-'):
                files.remove(item[1:])
            elif item.startswith('?'):
                fileRemove = item.split(' ')[0][1:]
                fileAdd = item.split(' ')[1]
                files.remove(fileRemove)
                if not item[1:] in files:
                    files.append(fileAdd)
            else:
                if not ignoreFaults:
                    raise Exception('There\'s an error in your history:\n  „{}“'.format(item))
                self.debug('There\'s an error in your history. Good for you that errors ar ignored...\n  „{}“'.format(item))
        return files


    def getHash(self, fin, hashtype='sha256'):
        """
        Generates hashsum of a file

        @param file: path to the file (relative or absolute)
        @type file: str
        @param hash: Type of hashsum, can be md5, sha1, sha224, sha256, sha384 or sha512
        @type hash: str
        @return: Returns hashsum of file including hashtype
        """
        if not fin.startswith(self.conf['syncfolder']):
            while fin.startswith('/'):  # This is neccessary: > os.path.join('/one', '/two')
                fin = fin[1:]           #                     > '/two'
            fin = os.path.join(self.conf['syncfolder'], fin)
        hashsumFile = eval('hashlib.{}()'.format(hashtype)) # executes for example „h = hashlib.sha256()“
        with open(fin, mode='rb') as f: # With updating the hashsum, the file size can be higher than the avaliable RAM
            while True:
                buf = f.read(4096)      # Maybe increase bufsize to get more speed?!
                if not buf:
                    break
                hashsumFile.update(buf)
        hashsum = eval('hashlib.{}()'.format(hashtype))
        text = '{}{}'.format(fin, hashsumFile.hexdigest())
        hashsum.update(text.encode('utf-8'))
        return '{}.{}'.format(hashsum.hexdigest(), hashtype)


    def connect(self):
        """
        Connects to server
        """
        try:
            if self.transport.is_active():
                return    # Return if a transport is already opened. This could cause problems if, for example, the transport is open but the sftpclient is inactive/dead/etc
        except AttributeError:  # self.transport is not defined, so we should open it
            pass
        self.transport = paramiko.Transport((self.conf['host'], self.conf['port']))
        self.sftp = None
        if self.conf['identityFile'] is None:
            self.debug('Use password login')
            try:
                self.transport.connect(username=self.conf['username'], password=self.askPassword('login'))
            except paramiko.ssh_exception.BadAuthenticationType:
                self.debug('Hm. Login with password doesn\'t work. Did you set „identityFile“ in {}?'.format(self.confFile))
                raise
        else:
            self.debug('Use identity file login')
            key = None
            identFile = os.path.expanduser(self.conf['identityFile'])
            try:
                key = paramiko.RSAKey.from_private_key_file(identFile)
            except paramiko.ssh_exception.PasswordRequiredException:
                key = paramiko.RSAKey.from_private_key_file(identFile, password=self.askPassword('Password for identity file:  '))
            self.transport.connect(username=self.conf['username'], pkey=key)
        self.sftp = paramiko.SFTPClient.from_transport(self.transport)
        self.debug('Connect to server {}:{}'.format(self.conf['host'], self.conf['port']))


    def disconnect(self):
        """
        Disconnects from server

        """
        self.sftp.close()
        self.transport.close()
        self.debug('Disconnect from server')


    def getLockName(self):
        """
        Get name of lock (who locked the server?)

        @return: Returns the name of the device which locked the server
        """
        self.sftp.chdir(self.conf['serverpath'])
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
        self.sftp.chdir(self.conf['serverpath'])
        if 'lock' in self.sftp.listdir(self.conf['serverpath']):
            if self.conf['name'] == self.getLockName():
                self.debug('Already locked (from this device)')
            else:
                self.debug('Already locked (from {})'.format(name))
                raise Exception('Cannot lock server directory (actually locked by {})'.format(name))
        else:
            with self.sftp.open('lock', 'w') as f:
                f.write(self.conf['name'])
            self.debug('Create lock')


    def unlock(self):
        """
        Unlocks server directory, asks if lock should be ignored (overwritten)
        """
        self.sftp.chdir(self.conf['serverpath'])
        if 'lock' in self.sftp.listdir(self.conf['serverpath']):
            if self.conf['name'] == self.getLockName():
                self.sftp.remove('lock')
                self.debug('Remove lock')
            else:
                if self.ask('Should the lock be ignored (overwrites lock)? ', 'bool'):
                    self.sftp.remove('lock')
                    self.debug('Overwrite lock - removing it')
        else:
            self.debug('Server is not locked')


    def compress(self, fin):
        """
        Compress a file

        @param fin: File input path, can be relative within the $syncfolder or absolute (but should still be withing $syncfolder)
        @type fin: str
        @return: Absolute path to compressed file (within cacheUp)
        """
        hashsum = self.getHash(fin)
        # Select compression mode
        modes = {'lzma' : 'w:xz',
                 'bzip2': 'w:bz2',
                 'gzip' : 'w:gz'
                 }
        mode = modes[self.conf['compression']]
        if mode is None: # Fallback
            mode = 'w'

        if not fin.startswith(self.conf['syncfolder']):
            while fin.startswith('/'):  # This is neccessary: > os.path.join('/one', '/two')
                fin = fin[1:]           #                     > '/two'
            fin = os.path.join(self.conf['syncfolder'], fin)
        fout = os.path.join(self.conf['cacheUp'], hashsum)
        with tarfile.open(fout, mode) as f:  # Use tarfile.open() instead of tarfile.TarFile() [look at the python docs for a reason]
            arcname = fin.replace(self.conf['syncfolder'], '', 1)
            f.add(fin, arcname)
        return fout


    def decompress(self, fin, delete=True):
        """
        Decompresses a file into $syncfolder

        @param fin: File input path, must be withing $cacheDown, can either be relative or absolute
        @type fin: str
        @param delete: If True, after decompressing the file will be removed
        @type delete: bool
        """
        if not fin.startswith(self.conf['cacheDown']):
            fin = os.path.join(self.conf['cacheDown'], fin)
        with tarfile.open(fin, 'r') as f:    # I don't know why, but we don't need to set a decompression algorithm. Not bad, isn't it.
            f.extractall(self.conf['syncfolder'])   # Direct extract into $syncfolder
        if delete:
            os.remove(fin)


    def encrypt(self, fin, fout, hashsum, uri, delete=True):
        """
        Encrypts a file

        @param fin: Input file, absolute path
        @type fin: str
        @param fin: Output file, absolute path
        @type fin: str
        @param delete: Delete input file (only works if not fin==fout)
        @type delete: bool
        """
        # TODO: Rewrite this, everyone using px aux oder top can view the passphrase
        #       Using the advanced python-gnupg mentioned in the Readme-section of this file!
        #print('Hint: Encryption is not safe!')
        #tmpfile = '{}.enc'.format(fout)
        #pw = self.genSymKey()
        ## Encrypt file
        #args = ['gpg', '--armor', '--symmetric', '--cipher-algo', 'aes256', '--output', tmpfile, '--batch', '--passphrase', pw, fin]
        #p = subprocess.Popen(args)
        ## Store password
        #alloc = None
        #with open(self.conf['allocation'], 'r') as f:
        #    alloc = json.loads(f.read())
        #alloc[hashsum] = (pw, uri)
        #with open(self.conf['allocation'], 'w') as f:
        #    f.write(json.dumps(alloc))
        ## Move to destination
        #shutil.move(tmpfile, fout)
        ## Remove fin if delete ist true and fin is not fout
        #if delete and fin != fout:
        #    os.remove(fin)
        ## Remove tmpfile
        #os.remove(tmpfile)
        pass


    def decrypt(self, fin, fout, hashsum, delete=True):
        """
        Decrypts a file

        @param fin: Input file, absolute path
        @type fin: str
        @param fin: Output file, absolute path
        @type fin: str
        @param delete: Delete input file (only works if not fin==fout)
        @type delete: bool
        """
        # TODO: Rewrite this, everyone using px aux oder top can view the passphrase
        #       Using the advanced python-gnupg mentioned in the Readme-section of this file!
        #print('Hint: Decryption is not safe!')
        #tmpfile = '{}.enc'.format(fout)
        ## Get password
        #pw = self.getKey(hashsum)
        ## Encrypt file
        #args = ['gpg', '--decrypt', '--output', tmpfile, '--batch', '--passphrase', pw, fin]
        #p = subprocess.Popen(args)
        ## Move to destination
        #shutil.move(tmpfile, fout)
        ## Remove fin if delete ist true and fin is not fout
        #if delete and fin != fout:
        #    os.remove(fin)
        pass


    def loadClientAllocation(self):
        """
        Loads the client allocation (from self.allocation)
        """
        pass


    def storeClientAllocation(self):
        """
        Stores the client allocation (from self.allocation)
        """
        pass


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
