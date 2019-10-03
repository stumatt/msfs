from Passthrough import Passthrough
import os
import subprocess

def encrypt(fr):
	#arriva il contenuto del file
	result="";
	for i in range(len(fr)):
		char = fr[i] #codice ASCII
		result += chr(char+1)
	return result


class teofs(Passthrough):
	def __init__(self,root):
		super().__init__(root)
	
	#Definisco un metodo che crea file
	def create_file(self,path,mode): 
		super().create(path,mode,fi=None)
		
	#Definisco un metodo che apre un file e lo legge
	def open_read(self,path,flags,size):
		f_opened = super().open(path,flags)
		f_readed = os.read(f_opened,size)
		print(f_readed)
	
	#Definisco un metodo che cifri il contenuto del file
	def open_encrypt(self,path,flags,size):
		self.flags=flags
		self.path=path
		f_opened = super().open(path,flags)
		f_readed = os.read(f_opened,size)
		subprocess.run(['mixslice','encrypt',"./TBM/cavia.txt"])
		#f_modified = encrypt(f_readed)
		
	def decrypt(self,path):
		subprocess.run(["mixslice","decrypt",path])
		
		
	
	#Definisco un metodo che elimina file
	def delete_file(self,path):
		full_path = super()._full_path(path)
		os.remove(full_path)
	
	
demo = teofs("/")
#demo.open_read("home/matteo/Desktop/Tesi/TBM/cavia.txt",os.O_RDONLY,500000)
demo.open_encrypt("home/matteo/Desktop/Tesi/TBM/cavia.txt",os.O_RDWR,500000)
print("ho crittato")
demo.decrypt("TBM/cavia.txt.enc")
print("ho decrittato")
#demo.create_file("home/matteo/Desktop/Tesi/TBM/appCreato.txt",0o777)
#demo.delete_file("home/matteo/Desktop/Tesi/TBM/appCreato.txt")

