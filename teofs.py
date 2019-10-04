from Passthrough import Passthrough
import os
import subprocess


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
		
	
		
		
		
demo = teofs("/")

#demo.read("home/matteo/Desktop/Tesi/TBM/cavia.txt",os.O_RDONLY,500000)
demo.encrypt("/mnt/MP/cavia.txt")
print("ho crittato")
demo.decrypt("/mnt/MP/cavia.txt.enc")
print("ho decrittato")

#demo.create_file("home/matteo/Desktop/Tesi/TBM/appCreato.txt",0o777)
#demo.delete_file("home/matteo/Desktop/Tesi/TBM/appCreato.txt")

