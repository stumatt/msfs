#!/usr/bin/python

from __future__ import with_statement

import os
import sys
import errno
from os import listdir
import tempfile
from pathlib import Path
from aesmix import MixSlice
import sha3
import datetime


from fuse import FUSE, FuseOSError, Operations

class Passthrough(Operations):
    
    
    def __init__(self, root, mountpoint):
        self.root = root
        self.mountpoint = mountpoint
        self.temp_dir =""
        self.locations = []
        self.isfirst = True
        self.listacorr = []
        self.corrTable = []

    # Helpers
    # =======

    def _full_path(self, partial):
        partial = partial.lstrip("/")
        path = os.path.join(self.root, partial)
        return path

    def save_ct(self,x):
        if x == 'r':
            print("[*] Realizing correspondace table")
            with open(self.temp_dir+'/corrtable',"w") as corrtable_file:
                for x in self.corrTable:
                    corrtable_file.write(x+',')
            print("[*] Correspondance table available under: ",self.temp_dir+"/corrtable")
        elif x == 'u':
            print("[*] Updating correspondace table")
            with open(self.temp_dir+'/corrtable',"w") as corrtable_file:
                for x in self.corrTable:
                    corrtable_file.write(x+',')
            print("[*] Updated correspondance table available under: ",self.temp_dir+"/corrtable")
        
    def decrypt(self,fragpath,plainpath):
        keyfile = (fragpath.replace(".enc",".public") if os.path.isfile(fragpath.replace(".enc",".public")) else fragpath.replace(".enc",".private"))
        assert os.path.isfile(keyfile), "key file not valid"
        print("[*] Start decrypting at: ",datetime.datetime.now())
        print("[*] Decrypting fragdir %s using key %s ..." %
                 (fragpath, keyfile))
        output = plainpath
        manager = MixSlice.load_from_file(fragpath,keyfile)
        plaindata = manager.decrypt()
        with open(output,"wb") as fp:
            fp.write(plaindata)
        print("[*] Decrypted file: %s" % output)
        print("[*] End decrypting at: ",datetime.datetime.now())
        
        #plain = self.open(output,os.O_RDONLY)
        #print(os.read(plain,1000))
    
    def encrypt(self,path):
        key = os.urandom(16)
        iv = os.urandom(16)
        output = path+".enc"
        public = path+".public"
        private = path+".private"
        with open(path,"rb") as f_opened:
            data = f_opened.read()
        print("Encrypting file %s ..." %path)
        manager = MixSlice.encrypt(data, key, iv)
        manager.save_to_files(output,public,private) #COME GENERA LE CHIAVI
        print("Output fragdir: %s" % output)
        print("Public key file:  %s" % public)
        print("Private key file: %s" % private)
    
    # Implemented filesystem methods
    # ==================
    # L'accesso alle directory e' fondamentale per questo filesystem, questo perche' i ciphertext sono directory di frammenti
    # dunque l'accesso ad una directory viene regolato in base al tipo di directory, se e' una fragdir allora l'accesso equivale 
    # ad una richiesta di decifratura se e' una directory qualsiasi invece viene permesso l'accesso come un qualsiasi file system
    
    def access(self, path, mode):
        full_path = self._full_path(path)
        print("You entered in: ",full_path)
        #se e' il primo accesso al mountpoint, touccha i file e crea tabella di corrisp e la mette in una lista che servira a fare da medium
        if full_path == self.root and self.isfirst == True: 
            toTouch = []
            dir = [d for d in listdir(full_path) if os.path.isdir(os.path.join(full_path,d))]  #apre e cerca in mnt/MP
            for x in dir:           
                if(x[-4:]==".enc"):
                    toTouch.append(x+".dec")
            if toTouch: #se c'e' almeno un directory .enc
                self.temp_dir = tempfile.mkdtemp(prefix="PLAIN") #creo una directory temporanea
                self.corrTable.append(self.mountpoint+','+self.temp_dir) #inizializzo la lista corrtable
                for x in toTouch: #per ogni fragdir nel mountpoint
                    Path(self.temp_dir+"/"+x).touch() #touccho il relativo decriptato
                    self.corrTable.append(x.replace(".dec","")+','+x) #ne aggiungo il nome alla corrtable sia del cipher che del plain
                self.save_ct('r') #salvo la corrtable in un file (INUTILE?????)
            
            self.isfirst = False #Questo mi permettere di fare tutto quello sopra solo al primo accesso ad MP
            
        
        if full_path[-4:] == ".enc":  #se si sta accendo ad una fragpath
            print('_'*80)
            s = input("ATTENZIONE: Sei entrato in una directory che contiene i frammenti di un file cifrato, vuoi decifrarlo? Y/N \n")
            x = True
            while x == True:
                if s == 'Y' or s == 'y':
                    with open(self.temp_dir+"/corrtable","r") as f:
	                    self.listacorr = (f.read().split(','))
	                    self.locations =[self.listacorr[0],self.listacorr[1]]
                    print(full_path)
                    if full_path.replace(self.root,"") in self.listacorr:    #e questa fragpath indirizza una vera fragdir            
                        index = self.listacorr.index(full_path.replace(self.root,""))
                        temporary_plain_path = self.temp_dir+'/'+self.listacorr[index+1] 
                        self.decrypt(full_path,temporary_plain_path) #decifro la fragdir e putto il plaintext nella /tmp/ nel file toucchato
                        self.listacorr.remove(full_path.replace(self.root,"")) #poppo la fragpath per motivi di ridondanda a questo if quando accedo per decifrarla
                        x = False
                elif s == 'n' or s == 'N':
                    print('_'*100)
                    print("ATTENZIONE: Sei in una fragdir, la compromissione di un solo frammento dentro questa directory rende impossibile la ricostruzione del plaintext!")
                    x = False
                else:
                    s = input("Input non valido! Inserisci Y/N \n")
                    x = True
                    
        if not os.access(full_path, mode):
            raise FuseOSError(errno.EACCES)
    
    def rmdir(self, path):
        full_path = self._full_path(path)
        print("Sto eliminando: ",full_path)
        if full_path[-4:] == '.enc': #Se stai eliminando una fragdir elimina anche le chiavi di decifratura ormai inutili
            os.rmdir(full_path)
            os.remove(full_path.replace(".enc",".public"))
            os.remove(full_path.replace(".enc",".private"))
        else:
            return os.rmdir(full_path)
            
    
    # Implemented file methods
    # ============
    
    def release(self, path, fh): #4
        full_path = self._full_path(path)
        if not os.path.isdir(full_path):            
            print("_"*80)
            print("Hai salvato il file: ",path)
            s = input("ATTENZIONE: Se non lo cifri prima di smontare andra' perso, vuoi cifrarlo? Y/N \n")
            x = True
            while x:
                if s == 'Y' or s == 'y':
                    self.encrypt(full_path)
                    print(full_path + " Encrypted")
                    self.corrTable.append(path.replace('/','')+".enc"+','+path.replace('/','')+".enc.dec")
                    self.save_ct('u')
                    x = False
                elif s == 'n' or s == 'N':
                    print("Potrai cifrarlo al prossimo save")
                    x = False
                else:
                    s = input("Non hai inserito correttamente. Digita Y o N! \n")
                    x = True                
        return os.close(fh)
    
    
    
    
    # Non implemented filesystem methods
    # ==================

    def chmod(self, path, mode):
        full_path = self._full_path(path)
        print("[*] Changing permission")
        os.chmod(full_path, mode)
        print("[*] Permission Changed")
        return

    def chown(self, path, uid, gid):
        full_path = self._full_path(path)
        return os.chown(full_path, uid, gid)

    def getattr(self, path, fh=None): #triggerato da ls, stat,...
        #print("[*] Giving info of: ",path)
        full_path = self._full_path(path)
        st = os.lstat(full_path)
        return dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime',
                     'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid'))

    def readdir(self, path, fh): #triggerato da ls, dir su directory
        full_path = self._full_path(path)
        print("Sto leggendo la directory",full_path)
        dirents = ['.', '..']
        if os.path.isdir(full_path):
            dirents.extend(os.listdir(full_path))
        for r in dirents:
            yield r

    def readlink(self, path): 
        pathname = os.readlink(self._full_path(path))
        print("Ho letto link: ",pathname)
        if pathname.startswith("/"):
            # Path name is absolute, sanitize it.
            return os.path.relpath(pathname, self.root)
        else:
            return pathname

    def mknod(self, path, mode, dev):
        return os.mknod(self._full_path(path), mode, dev)

    

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
        return os.symlink(name, self._full_path(target))

    def rename(self, old, new):
        return os.rename(self._full_path(old), self._full_path(new))

    def link(self, target, name):
        return os.link(self._full_path(target), self._full_path(name))

    def utimens(self, path, times=None):
        return os.utime(self._full_path(path), times)

    # Non implemented file methods
    # ============

    def open(self, path, flags): #1
        if path[-4:] == ".dec":
            print("plaintext: " ,path, "opened")
            return os.open(path,flags)
        else:
            full_path = self._full_path(path)
            print(full_path, "opened")
        return os.open(full_path, flags)

    def create(self, path, mode, fi=None):
        full_path = self._full_path(path)
        print("Sto creando: ",full_path)
        return os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)

    def read(self, path, length, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        return os.read(fh, length)

    def write(self, path, buf, offset, fh): #2
        print("sto scrivendo ",path)
        os.lseek(fh, offset, os.SEEK_SET)
        return os.write(fh, buf)

    def truncate(self, path, length, fh=None):
        full_path = self._full_path(path)
        print("sto troncando ", full_path)
        with open(full_path, 'r+') as f:
            f.truncate(length)

    def flush(self, path, fh): #forces write of file with file descriptor fd to disk #3
        print("sto forzando il write  ",path)
        return os.fsync(fh)
       
    def fsync(self, path, fdatasync, fh):
        print("sto flushando ",path)
        return self.flush(path, fh)


def main(mountpoint, root, masterpassword):
    pw = ''.join(open(root+"password").read().split('\n'))
    mphashed = sha3.keccak_512(masterpassword.encode('utf_8')).hexdigest()
    if pw == mphashed:
        print("Password accepted")
        FUSE(Passthrough(root,mountpoint), mountpoint, nothreads=True, foreground=True)     
    else:
        print("Masterpassword sbagliata")

if __name__ == '__main__':
    main(sys.argv[2], sys.argv[1], sys.argv[3])
