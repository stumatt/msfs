from Passthrough import Passthrough
import os
import subprocess
from aesmix import mixencrypt, mixdecrypt
from aesmix import t_mixencrypt, t_mixdecrypt
from aesmix import mix_and_slice, unslice_and_unmix
from aesmix import keyreg
from aesmix import MixSlice
from six.moves import xrange
import argparse
import logging
import os.path



'''
def test_multi_thread():
    print("\n\nTest multi thread")
    key = b"k" * 16
    iv = b"i" * 16
    threads = 8

    plaintext = b"d" * (2 ** 20) * 128  # 128 MiB
    print("plaintext: %s ... %s" % (plaintext[:64], plaintext[-64:]))

    ciphertext = t_mixencrypt(plaintext, key, iv, threads, to_string=True)
    print("ciphertext: %r ... %r" % (ciphertext[:64], ciphertext[-64:]))

    decrypted = t_mixdecrypt(ciphertext, key, iv, threads, to_string=False)
    print("decrypted: %s ... %s" % (decrypted[:64], decrypted[-64:]))
'''

def encrypt():
    key = b"k" * 16
    iv = b"i" * 16
    path = input("inserisci path: ")
    output = path[-9:]+".enc"       #FUNZIONA PER CAVIA.TXT
    public = path[-9:]+".public"
    private = path[-9:]+".private"
    print(output)
    with open(path,"rb") as f_opened:
        data = f_opened.read()
    print(data)
    manager = MixSlice.encrypt(data, key, iv)
    manager.save_to_files(output,public,private) #COME GENERA LE CHIAVI

    
def decrypt():
    fragpath = input("inserisci path fragdir:")
    keyfile = fragpath[-13:-4]+".private"
    output = fragpath[-13:]+".dec"
    manager = MixSlice.load_from_file(fragpath,keyfile)
    plaindata = manager.decrypt()
    with open(output,"wb") as fp:
        fp.write(plaindata)
    
    
    
encrypt()  
decrypt()



    