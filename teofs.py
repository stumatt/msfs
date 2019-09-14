from Passthrough import Passthrough
import os

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
	
	#Definisco un metodo che apre un file e lo legge
	def open_read(self,path,flags,size):
		f_opened = super().open(path,flags)
		f_readed = os.read(f_opened,size)
		print(f_readed)
	
	def open_write(self,path,flags,size):
		f_opened = super().open(path,flags)
		f_readed = os.read(f_opened,size)
		f_modified = encrypt(f_readed)
		print(f_modified)
	
	
		
	
		
demo = teofs("/")
#demo.open_read("home/matteo/Desktop/Tesi/TBM/cavia.txt",os.O_RDONLY,500000)
demo.open_write("home/matteo/Desktop/Tesi/TBM/cavia.txt",os.O_RDWR,500000)