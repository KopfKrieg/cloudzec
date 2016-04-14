# ![CloudZec sync](images/cloudzec_logo_mid.png) #

CloudZec sync (short „CloudZec“) is a free synchronisation solution with end-to-end encryption, based on stable technologies like GnuPG and SFTP.

## Features ##
- No additional server software required
- End-to-end encryption
- Free Software
- Usable without any graphical user interface
- Uses file based deduplication

## Installation ##

### General ###
- Install python3
- Install the python3 version of paramiko
- Install python3-gnupg or (better) the following fork: [python-gnupg](https://github.com/isislovecruft/python-gnupg)
- For notification support install python3-notify2
- For the CloudZec icon in notifications install the python3 version of GObject Introspection
- For keyring support install python3-keyring
- Clone the repository
- Follow the instructions under „Run CloudZec sync“

### Arch Linux ###
- Install cloudzec-git from AUR
- For notification support install python-notify2 from AUR
- For the CloudZec icon in notifications install python-gobject from extra
- For keyring support install python-keyring from AUR
- Follow the instructions under „Run CloudZec sync“

### Ubuntu 14.04 | Debian 8  ###
Pyhton3 is still not the standard python interpreter on Ubuntu (or Debian) and due to the lack of python3 support you need to build python3-paramiko yourself. Just follow the instructions, it's easy:

#### Install the dependencies ####
```sudo apt-get install python3 python3-gnupg python3-crypto python3-ecdsa```

- For notification support install python3-notify2
- For the CloudZec icon in notifications install python3-gi
- For keyring support install python3-keyring

#### Setup paramiko ####
```
wget "http://pypi.python.org/packages/source/p/paramiko/paramiko-1.13.0.tar.gz"
tar -xf paramiko-1.13.0.tar.gz
mkdir build
cd paramiko-1.13.0/
python3 setup.py install --root="./../build/" --optimize=1
cd ..
```

#### Get CloudZec sync ####
```git clone http://github.com/KopfKrieg/cloudzec.git```

#### Throw all in one directory ####
```
mkdir run
mv build/usr/local/lib/python3.4/dist-packages/paramiko run/
cp cloudzec/cloudzec run/cloudzec
cp cloudzec/libcloudzec.py run/libcloudzec.py
mkdir run/icon
cp cloudzec/icon/cloudzec_48.png run/icon/cloudzec_48.png
```

You can now run CloudZec sync from ```run``` via ```./cloudzec```

## Run CloudZec sync ##

### On the first start, do the following ###
- Run ```cloudzec --init```
- Edit your config-file (```~/.cloudzec/cloudzec.conf```)
- Run ```cloudzec --remoteinit```
- Done

### General options ###
There are only a few options for ```cloudzec```:
- -h, --help → Shows the help
- -v, --verbose → Show debug messages
- -i, --init → Initialise the local repository
- -r, --remoteinit → Initialise the remote repository
- -s, --sync → Full sync between remote and local repository
- -d [time], --daemon [time] → Full sync between remote and local repository, [time] specifies the time between syncs in minutes (default 15 minutes)

## License ##

Look at the LICENSE file (short version: GPLv3+)

## Website ##

Yep, there's a website: [cloudzec.kopfkrieg.org](http://cloudzec.kopfkrieg.org)
