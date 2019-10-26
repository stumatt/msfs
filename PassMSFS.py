#!/usr/bin/env python

from __future__ import with_statement

from os import listdir
import os
import sys
import errno
import tempfile
from pathlib import Path

from fuse import FUSE, FuseOSError, Operations


class Passthrough(Operations):
    
    
    def __init__(self, root, mountpoint):
        self.root = root
        self.mountpoint = mountpoint
        self.temp_dir =""
        self.locations = []
        self.isfirst = True
        self.listacorr = []

    # Helpers
    # =======
            
    def _full_path(self, partial):
        if partial.startswith("/"):
            partial = partial[1:]
        path = os.path.join(self.root, partial)
        return path
    
    def save_ct(self,ct):
        print("[*] Realizing correspondace table")
        with open(self.temp_dir+'/corrtable',"w") as corrtable_file:
            for x in ct:
                corrtable_file.write(x+os.linesep)
        print("Correspondance table available under: ",self.temp_dir+"corrtable")
        return

    # Filesystem methods
    # ==================

    def access(self, path, mode):
        full_path = self._full_path(path)
        print("Sono entrato in: ",full_path)
        #se e' il primo accesso al mountpoint, touccha i file e crea tabella di e la mette in una lista che servira a fare da medium
        if full_path == self.root and self.isfirst == True: 
            toTouch = []
            dir = [d for d in listdir(full_path) if os.path.isdir(os.path.join(full_path,d))]  #potrei aggiungere di filtrare le nonvuote
            for x in dir:           
                if(x[-4:]==".enc"):
                    toTouch.append(x+".dec")
            if toTouch:
                self.temp_dir = tempfile.mkdtemp(prefix="PLAIN")
                corrTable = [self.mountpoint+','+self.temp_dir]
                print(self.temp_dir)
                for x in toTouch:
                    Path(self.temp_dir+"/"+x).touch()
                    corrTable.append(x.replace(".dec","")+','+x+',')
                self.save_ct(corrTable);
                
            with open(self.temp_dir+"/corrtable","r") as fr:
                self.locations = fr.readline().split(',',1) #mountpoint in locations[0], temp in locations[1]                       
            
            with open(self.temp_dir+"/corrtable","r") as f:
                next(f)
                self.listacorr = f.read().split(',')
            
            #a questo appunto siamo in una situazione in cui locations contiene path mountpoint e path temporanea
            #e listacorr contiene cipher e plain uno adiacente all'altro, vanno sommati alle locations.
                
            self.isfirst = False 
        
        
        if full_path[-4:] == ".enc":
            cip_index = self.listacorr.index(full_path.replace(self.root,"")) 
            print(cip_index) 
            '''for x in self.listacorr:
                if x == full_path
            print("sei entrato in una fragdir, questa: ",full_path)'''
            
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
        print("Ho letto il contenuto della dir: ",full_path)

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
    if pw == masterpassword:
        FUSE(Passthrough(root,mountpoint), mountpoint, nothreads=True, foreground=True)     
    else:
        print("Masterpassword sbagliata")

if __name__ == '__main__':
    main(sys.argv[2], sys.argv[1], sys.argv[3])