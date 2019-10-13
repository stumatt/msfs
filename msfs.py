from Passthrough import Passthrough
import os
from os import listdir
from collections import namedtuple
import tempfile
import json
from aesmix import mixencrypt, mixdecrypt
from aesmix import t_mixencrypt, t_mixdecrypt
from aesmix import keyreg
from aesmix import MixSlice


class msfs(Passthrough):
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
	def read(self,path):
		with open(path,"rb") as f_opened:
			data = f_opened.read()
		print(data)
	
	#Definisco un metodo che cifri il contenuto del file
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
		
	#Definisco un metodo che faccia policy update	
	def update(self,fragpath):
		public = fragpath.replace(".enc",".public")
		private = fragpath.replace(".enc",".private")
		print("Performing policy update on %s ..." %fragpath)
		manager = MixSlice.load_from_file(fragpath,private)
		manager.step_encrypt()
		manager.save_to_files(fragpath,public,private)
		print("Done")
		
				
    #Definisco un metodo che decifri il contento della cartella contenente i datagrammi e ricostruisca il plaintext
	def decrypt(self,fragpath):
		keyfile = (fragpath.replace(".enc",".public") if os.path.isfile(fragpath.replace(".enc",".public")) else fragpath.replace(".enc",".private"))
		assert os.path.isfile(keyfile), "key file not valid"
		print("Decrypting fragdir %s using key %s ..." %
                 (fragpath, keyfile))
		output = fragpath+".dec"
		manager = MixSlice.load_from_file(fragpath,keyfile)
		plaindata = manager.decrypt()
		with open(output,"wb") as fp:
			fp.write(plaindata)
		print("Decrypted file: %s" % output)
		
	def temporize(self):
		path = "/mnt/MP/"
		#creo una lista contenente i nomi delle directory di frammenti nel mountpoint
		int_dir=[]
		int_files=[]
		dir = [d for d in listdir(path) if os.path.isdir(os.path.join(path,d))]
		for x in dir:
			if(x[-4:] ==".enc"):
				int_dir.append(x)
		for x in int_dir:  #Decritto ogni directory
			print(x)
			self.decrypt(path+x)
		allfiles = [f for f in listdir(path) if os.path.isfile(os.path.join(path,f))]
		for x in allfiles:
			if(x[-4:]==".dec"):
				int_files.append(x)
		temp_file_dict = {}	#dizionario di corrispondenza file - filetemp
		table = [] #lista di corrispondenze files - filestemp	
		i = 0
		temp_dir = tempfile.mkdtemp()
		temp_file_dict['Temporary plaintext directory']=temp_dir
		for x in int_files:
			with open((path+x),"rb") as fr:				
				data = fr.read()
			temp = tempfile.NamedTemporaryFile(mode='w+b',delete=False, dir=temp_dir) 
			temp.write(data)
			temp_file_dict['ciphertext'] = (path+x).replace(".dec","")
			temp_file_dict['plaintext'] = temp.name
			tablepath=path+"corrTable"
			exTempDict = {'exTempDict':temp_file_dict}
			#Scrivo la tabella di corrispondere tra ciphertext nel MP e file temporanei nel /tmp
			with open(tablepath,"a") as ftable:
				ftable.write(json.dumps(exTempDict))
				ftable.write("\n")
			self.delete_file(path+x)
		
			
			
		'''
		files = [f for f in listdir(path) if os.path.isfile(os.path.join(path,f))]
		for x in files:
			if(x[-7:]!="private" and x[-6:]!="public"):
				files.remove(x)
		#A sto punto in files ho le path che mi servono quindi sposto i file delle chiavi in file temporanei /tmp/
		temp_file_dict = {}	#dizionario di corrispondenza file - filetemp
		table = [] #lista di corrispondenze files - filestemp
		for x in files:
			with open((path+x),"rb") as fr:				
				temp_file_dict['filename'] = path+x
				temp = tempfile.NamedTemporaryFile(mode='w+b',delete=False) 
				temp.write(fr.read())
				temp_file_dict['tempname'] = temp.name
				table.append(temp_file_dict)
		for x in table:
			print(x)
		'''
	
		
		
demo = msfs("/")
'''
scelta = input("Cosa vuoi fare? \n 1: Scegli un file e cifralo \n 2: Scegli un file cifrato e decifralo \n 3: Revoca accesso a file \n 4: leggi file cavia \n")
if(scelta == '1'):
	path = input("inserisci la path del file da crittografare \n")
	#if path[0:8]=="/mnt/MP/":
		#demo.encrypt(path)
	demo.encrypt(path)
elif(scelta == '2'): 
	path = input("inserisci la path della fragdir \n")
	#if path[0:8]=="/mnt/MP/":
		#demo.decrypt(path)	
	demo.decrypt(path)
elif(scelta == '3'):
	path = input("inserisci la path del file da revocare \n")
	#if path[0:8]=="/mnt/MP/":
	demo.update(path)
elif(scelta == '4'): demo.read("/home/matteo/Desktop/Tesi/TBM/cavia.txt")	
else: print("niente di buono \n")
'''
demo.temporize()



#demo.read("home/matteo/Desktop/Tesi/TBM/cavia.txt",os.O_RDONLY,500000)
#demo.encrypt("/mnt/MP/cavia.txt")

#demo.decrypt("/mnt/MP/cavia.txt.enc")
#print("ho decrittato")

#demo.create_file("home/matteo/Desktop/Tesi/TBM/appCreato.txt",0o777)
#demo.delete_file("home/matteo/Desktop/Tesi/TBM/appCreato.txt")
