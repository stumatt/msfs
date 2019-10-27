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

    def save_ct(self):
        print("[*] Realizing correspondace table")
        with open(self.temp_dir+'/corrtable',"w") as corrtable_file:
            for x in self.corrTable:
                corrtable_file.write(x+',')
        print("[*] Correspondance table available under: ",self.temp_dir+"/corrtable")
        
    def decrypt(self,fragpath,plainpath):
        keyfile = (fragpath.replace(".enc",".public") if os.path.isfile(fragpath.replace(".enc",".public")) else fragpath.replace(".enc",".private"))
        assert os.path.isfile(keyfile), "key file not valid"
        print("[*] Decrypting fragdir %s using key %s ..." %
                 (fragpath, keyfile))
        output = plainpath
        manager = MixSlice.load_from_file(fragpath,keyfile)
        plaindata = manager.decrypt()
        with open(output,"wb") as fp:
            fp.write(plaindata)
        print("[*] Decrypted file: %s" % output)
    
    # Filesystem methods
    # ==================

    def access(self, path, mode):
        full_path = self._full_path(path)
        print("Sono entrato in: ",full_path)
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
                self.save_ct() #salvo la corrtable in un file (INUTILE?????)
            
            self.isfirst = False #Questo mi permettere di fare tutto quello sopra solo al primo accesso ad MP
            
            with open(self.temp_dir+"/corrtable","r") as f:
	            self.listacorr = (f.read().split(','))
	            self.locations =[self.listacorr[0],self.listacorr[1]]
        
        if full_path[-4:] == ".enc":  #se si sta accendo ad una fragpath
            if full_path.replace(self.root,"") in self.listacorr:    #e questa fragpath indirizza una vera fragdir            
                index = self.listacorr.index(full_path.replace(self.root,""))
                temporary_plain_path = self.temp_dir+'/'+self.listacorr[index+1] 
                self.decrypt(full_path,temporary_plain_path) #decifro la fragdir e putto il plaintext nella /tmp/ nel file toucchato
                self.listacorr.remove(full_path.replace(self.root,"")) #poppo la fragpath per motivi di ridondanda a questo if quando accedo per decifrarla       
                
            else:
                print("Hai gia' decifrato questo file")
            
            
        
        if not os.access(full_path, mode):
            raise FuseOSError(errno.EACCES)

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

    def readdir(self, path, fh):
        full_path = self._full_path(path)

        dirents = ['.', '..']
        if os.path.isdir(full_path):
            dirents.extend(os.listdir(full_path))
        for r in dirents:
            yield r

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
        return os.symlink(name, self._full_path(target))

    def rename(self, old, new):
        return os.rename(self._full_path(old), self._full_path(new))

    def link(self, target, name):
        return os.link(self._full_path(target), self._full_path(name))

    def utimens(self, path, times=None):
        return os.utime(self._full_path(path), times)

    # File methods
    # ============

    def open(self, path, flags):
        full_path = self._full_path(path)
        print("CI SIAMO")
        return os.open(full_path, flags)

    def create(self, path, mode, fi=None):
        full_path = self._full_path(path)
        return os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)

    def read(self, path, length, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        return os.read(fh, length)

    def write(self, path, buf, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        return os.write(fh, buf)

    def truncate(self, path, length, fh=None):
        full_path = self._full_path(path)
        with open(full_path, 'r+') as f:
            f.truncate(length)

    def flush(self, path, fh):
        return os.fsync(fh)

    def release(self, path, fh):
        return os.close(fh)

    def fsync(self, path, fdatasync, fh):
        return self.flush(path, fh)


def main(mountpoint, root, masterpassword):
    pw = ''.join(open(root+"password").read().split('\n'))
    print(pw)
    mphashed = sha3.keccak_512(masterpassword.encode('utf_8')).hexdigest()
    print(mphashed)
    if pw == mphashed:
        FUSE(Passthrough(root,mountpoint), mountpoint, nothreads=True, foreground=True)     
    else:
        print("Masterpassword sbagliata")

if __name__ == '__main__':
    main(sys.argv[2], sys.argv[1], sys.argv[3])
