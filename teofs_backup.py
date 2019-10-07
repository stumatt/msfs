from Passthrough import Passthrough
import os
import subprocess
from aesmix import mixencrypt, mixdecrypt
from aesmix import t_mixencrypt, t_mixdecrypt
from aesmix import mix_and_slice, unslice_and_unmix
from aesmix import keyreg
from aesmix import MixSlice


class teofs(Passthrough):
	def __init__(self,root):
		super().__init__(root)
	
	#Definisco un metodo che crea file
	def create_file(self,path,mode): 
		super().create(path,mode,fi=None)
		
	#Definisco un metodo che elimina file
	def delete_file(self,path):
		full_path = super()._full_path(path)
		os.remove(full_path)
		
	#Definisco un metodo che apre un file e lo legge
	def read(self,path,flags,size):
		f_opened = super().open(path,flags)
		f_readed = os.read(f_opened,size)
		print(f_readed)
	
	#Definisco un metodo che cifri il contenuto del file
	def encrypt(self,path):
		subprocess.run(['mixslice','encrypt',path])
		
	#Definisco un metodo che decifri il contento della cartella contenente i datagrammi e ricostruisca il plaintext
	def decrypt(self,path):
		subprocess.run(["mixslice","decrypt",path])
		
	def revaccess(self,path):
		subprocess.run(["mixslice","update",path])
		
	
		
		
		
demo = teofs("/")
scelta = input("Cosa vuoi fare? \n 1: Scegli un file e cifralo \n 2: Scegli un file cifrato e decifralo \n 3: Revoca accesso a file \n 4: leggi file cavia \n")
if(scelta == '1'):
	path = input("inserisci la path del file da crittografare \n")
	if path[0:8]=="/mnt/MP/":
		demo.encrypt(path)
elif(scelta == '2'): 
	path = input("inserisci la path del file da decrittare \n")
	if path[0:8]=="/mnt/MP/":
		demo.decrypt(path)	
elif(scelta == '3'):
	path = input("inserisci la path del file da revocare \n")
	if path[0:8]=="/mnt/MP/":
		demo.revaccess(path)
elif(scelta == '4'): demo.read("/mnt/MP/cavia.txt",os.O_RDONLY,500000)	
else: print("niente di buono \n")




#demo.read("home/matteo/Desktop/Tesi/TBM/cavia.txt",os.O_RDONLY,500000)
#demo.encrypt("/mnt/MP/cavia.txt")

#demo.decrypt("/mnt/MP/cavia.txt.enc")
#print("ho decrittato")

#demo.create_file("home/matteo/Desktop/Tesi/TBM/appCreato.txt",0o777)
#demo.delete_file("home/matteo/Desktop/Tesi/TBM/appCreato.txt")

