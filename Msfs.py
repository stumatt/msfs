#!/usr/bin/env python

from __future__ import with_statement

from getpass import getpass
import time
import os
import sys
import errno
from os import listdir
import tempfile
from pathlib import Path
from aesmix import MixSlice
import sha3
import datetime
import pyAesCrypt
import stat
from fuse import FUSE, FuseOSError, Operations

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
class Passthrough(Operations):
    def __init__(self, root, mountpoint, mp):
        self.root = root
        self.mountpoint = mountpoint
        self.masterpassword = mp
        self.decrypted = []
        self.openedfile = []
        self.openedfilesize = []
        self.buffersize = 64*1024
        self.TouchedDir = []
        self.modified = []
        self.unlockedDir = []
        

    # Helpers
    # =======

    def _full_path(self, partial):
        if partial.startswith("/"):
            partial = partial[1:]
        path = os.path.join(self.root, partial)
        return path
    
    def keydecryption(self, enckey):
        size = os.stat(enckey).st_size
        with open(enckey,'rb') as fin:
            try:
                deckey = tempfile.NamedTemporaryFile(delete=False)
                print("chiave decifrata in: ",deckey.name)
                with open(deckey.name,'wb') as fout:
                    pyAesCrypt.decryptStream(fin,fout,self.masterpassword,self.buffersize,size)
            except ValueError:
                print("errore")
        return deckey.name
    

    def keyencryption(self,public,private):
        pyAesCrypt.encryptFile(public,public+".aes",self.masterpassword,self.buffersize)
        pyAesCrypt.encryptFile(private,private+".aes",self.masterpassword,self.buffersize)
        os.remove(public)
        os.remove(private)
        
        
    def decrypt(self,fragpath,plainpath):
        keyfile = (fragpath.replace(".enc",".public.aes") if os.path.isfile(fragpath.replace(".enc",".public.aes")) else fragpath.replace(".enc",".private.aes"))
        assert os.path.isfile(keyfile), "key file not valid"
        keyfile = self.keydecryption(keyfile) #ritorna deckey
        #print("[*] Start decrypting at: ",datetime.datetime.now())
        print("[*] Decrypting fragdir %s using key %s ..." %
                 (fragpath, keyfile))
        output = plainpath
        manager = MixSlice.load_from_file(fragpath,keyfile)
        plaindata = manager.decrypt()
        with open(output,"wb") as fp:
            fp.write(plaindata)
        os.remove(keyfile) #La chiave temporanea viene eliminata
        print("[*] Decrypted file: %s" % output)
        #print("[*] End decrypting at: ",datetime.datetime.now())
        time.sleep(1)
    
    
    def encrypt(self,path):
        if path[-8:] == ".enc.dec":
            newpath = path.replace(".enc.dec","")
        else:
            newpath = path
        print(path)
        key = os.urandom(16)
        iv = os.urandom(16)
        output = newpath+".enc"
        public = newpath+".public"
        private = newpath+".private"
        with open(path,"rb") as f_opened:
            data = f_opened.read()
        print("Encrypting file %s ..." %path)
        manager = MixSlice.encrypt(data, key, iv)
        manager.save_to_files(output,public,private) #COME GENERA LE CHIAVI
        print("Output fragdir: %s" % output)
        print("Public key file:  %s" % public)
        print("Private key file: %s" % private)
        os.remove(path)
        self.keyencryption(public,private)
        
    
    def touch(self,fname, times=None):
        with open(fname, 'a'):
            os.utime(fname, times)
            
    def fillDir(self,full_path,mode):
        if full_path not in self.TouchedDir: #Se e' il primo accesso a questa dir, touccha i .dec relativi ai .enc in questa dir
            print("[*] Touching file")
            toTouch = []
            dir = [d for d in listdir(full_path) if os.path.isdir(os.path.join(full_path,d)) and d[-4:]==".enc"]  #preleva tutte le directories
            for x in dir:
                toTouch.append(x+".dec") # preleva quelle da toucchare
            if toTouch: #se c'e' almeno un directory .enc
                for x in toTouch: #per ogni fragdir nel mountpoint
                    self.touch(full_path+"/"+x)
            self.TouchedDir.append(full_path)#Tengo traccia delle directory che hanno subito touch
        else:
            if not os.access(full_path, mode):
                raise FuseOSError(errno.EACCES)
        
        
        
        
    # Filesystem methods
    # ==================

    def access(self, path, mode): #triggerato quando si entra in una directory
        full_path = self._full_path(path)
        if full_path == self.root:
            self.fillDir(full_path,mode)
        elif full_path != self.root and full_path not in self.unlockedDir and os.path.isdir(full_path):
            print(bcolors.WARNING+"You are trying to entry in:", path +" folder" +bcolors.ENDC)
            print(bcolors.OKGREEN+"Access to ", path+" allowed" + bcolors.ENDC)
            self.fillDir(full_path,mode)
            self.unlockedDir.append(full_path)           
                
                
    def readdir(self, path, fh): #triggerato quando si visualizza il contenuto di una directory
        full_path = self._full_path(path) #trasforma il path passato in fullpath
        
        dirents = ['.', '..']
        toFilter = [] #lista di tutti i file e le directory presenti nella directory aperta
        filtered = [] #lista di quelli ch vanno bene
        if os.path.isdir(full_path): #se stai entrando in una directory
            if(full_path[-1:]!='/'): 
                full_path = full_path+'/'
            toFilter.extend(os.listdir(full_path)) #preleva tutti file e directories
            for x in toFilter:
                if(x[-4:] == ".dec") or (os.path.isdir(full_path+x) and not x[-4:] == ".enc"): #Se e' un .dec, o una directory di non frammenti
                    filtered.append(x)                
        dirents.extend(filtered)
        for r in dirents:
            yield r      
    
    
    def destroy(self,path): #triggerato dall'unmount del filesystem 
        if self.modified:
            print(bcolors.WARNING+"Hai modificato i seguenti file: "+bcolors.ENDC)
            for m in self.modified: 
                print(m)
            x = True
            while(x):
                s = input(bcolors.WARNING+"Vuoi cifrarli? Y/N "+bcolors.ENDC)
                if s == 'Y' or s == 'y':
                    for m in self.modified:
                        self.encrypt(m)
                    x = False
                elif s =='N' or s == 'n':
                    print("I file modificati verranno eliminati")
                    x = False
                                      
        print("[*] Unmounting filesystem under", self.mountpoint)
        for filename in Path(self.root).rglob('*.dec'): #Va a rimuovere tutti i .dec toucchati o riempiti
                os.remove(filename)
                print("[*] Deleting: ",filename)
                
                             
    def chmod(self, path, mode):
        full_path = self._full_path(path)
        return os.chmod(full_path, mode)

    def chown(self, path, uid, gid):
        full_path = self._full_path(path)
        return os.chown(full_path, uid, gid)

    def getattr(self, path, fh=None):
        full_path = self._full_path(path)
        st = os.lstat(full_path)
        return dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime',
                     'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid'))                               

    def readlink(self, path):
        pathname = os.readlink(self._full_path(path))
        if pathname.startswith("/"):
            # Path name is absolute, sanitize it.
            return os.path.relpath(pathname, self.root)
        else:
            return pathname

    def mknod(self, path, mode, dev):
        return os.mknod(self._full_path(path), mode, dev)

    def rmdir(self, path):
        full_path = self._full_path(path)
        return os.rmdir(full_path)

    def mkdir(self, path, mode):
        return os.mkdir(self._full_path(path), mode)

    def statfs(self, path):
        full_path = self._full_path(path)
        stv = os.statvfs(full_path)
        return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree',
            'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files', 'f_flag',
            'f_frsize', 'f_namemax'))

    def unlink(self, path):
        return os.unlink(self._full_path(path))

    def symlink(self, name, target):
        return os.symlink(target, self._full_path(name))

    def rename(self, old, new):
        return os.rename(self._full_path(old), self._full_path(new))

    def link(self, target, name):
        return os.link(self._full_path(name), self._full_path(target))

    def utimens(self, path, times=None):
        return os.utime(self._full_path(path), times)

    # File methods
    # ============

    def open(self, path, flags):
        full_path = self._full_path(path)
        os.chmod( full_path, stat.S_IWRITE | stat.S_IREAD )
        if full_path not in self.openedfile:
            self.openedfile.append(full_path)
            self.openedfilesize.append(os.stat(full_path).st_size)
        
        if full_path not in self.decrypted:
            self.decrypt(full_path.replace(".dec",""),full_path)
            self.decrypted.append(full_path)
        
        return os.open(full_path, os.O_RDWR, mode=0o777)

    def flush(self, path, fh): #triggherato quando un file viene importato
        full_path = self._full_path(path)
        if not os.path.isdir(full_path) and full_path not in self.openedfile:            
            print("Hai importato il file: " , path)
            s = input(bcolors.WARNING + "ATTENZIONE: Se non lo cifri prima di smontare andra' perso, vuoi cifrarlo? Y/N \n" + bcolors.ENDC)
            x = True
            while x:
                if s == 'Y' or s == 'y':
                    self.encrypt(full_path)
                    Path(full_path+".enc.dec").touch()
                    x = False
                elif s == 'n' or s == 'N':
                    print("Potrai cifrarlo al prossimo save")
                    x = False
                else:
                    s = input(bcolors.FAIL+"Non hai inserito correttamente. Digita Y o N! \n"+bcolors.ENDC)
                    x = True
                    
    def truncate(self, path, length, fh=None):
        full_path = self._full_path(path)
        if full_path not in self.modified:
            self.modified.append(full_path)
        with open(full_path, 'r+') as f:
            f.truncate(length)
                    
                    
    def create(self, path, mode, fi=None):
        full_path = self._full_path(path)
        return os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)

    def read(self, path, length, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        return os.read(fh, length)

    def write(self, path, buf, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        return os.write(fh, buf)

    def release(self, path, fh):   
        return os.close(fh)            
            

    def fsync(self, path, fdatasync, fh):
        return self.flush(path, fh)


    
def main(mountpoint, root):
    pw = ''.join(open(root+".password").read().split('\n'))
    print(bcolors.WARNING+"Insert master password to start the mounting operation: "+bcolors.ENDC)
    masterpassword = getpass()
    mphashed = sha3.keccak_512(masterpassword.encode('utf_8')).hexdigest()
    if pw == mphashed:
        print(bcolors.OKGREEN + "Password accepted, filesystem mounted" + bcolors.ENDC)
        FUSE(Passthrough(root,mountpoint,masterpassword), mountpoint, nothreads=True, foreground=True)     
    else:
        print(bcolors.FAIL + "Masterpassword sbagliata" + bcolors.ENDC)

if __name__ == '__main__':
    main(sys.argv[2], sys.argv[1])
