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
import threading
import subprocess
import time
import shutil




#Helpers
def launchPass():
	p = subprocess.run(["python","/home/matteo/Desktop/Tesi/Passthrough.py","TBM/","/mnt/MP/"])
	
	

#FileSystem Methods
class msfs(Passthrough):
	def __init__(self,root):
		super().__init__(root)
	
	#Helpers 
	def set_temp_dir(self,path): #Per avere sempre la path della directory temporanea che contiene i plaintext
		self.tempdir = path
	
	def set_corrtable(self,path): #Per avere sempre la path del file che contiene le corrispondenze fra ciphertext e plaintext
		self.corrtable = path
	
	def print_table(self):
		self.read(self.corrtable)
				
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
			data = f_opened.readline()
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
		
	def temporize(self,path):
		#creo una lista contenente i nomi delle directory di frammenti nel mountpoint
		int_dir=[] #Directory dei frammenti
		int_files=[] #
		dir = [d for d in listdir(path) if os.path.isdir(os.path.join(path,d))] #Prendo ogni cartella nel mountpoint
		for x in dir: #Prelevo solo quelle contenenti frammenti
			if(x[-4:] ==".enc"):
				int_dir.append(x) 
		for x in int_dir:  #Decritto ogni directory contenente frammenti
			self.decrypt(path+x)
			
		allfiles = [f for f in listdir(path) if os.path.isfile(os.path.join(path,f))] #Prelevo tutti i file nel mountpoint
		for x in allfiles: #Prelevo solo i file .dec
			if(x[-4:]==".dec"):
				int_files.append(x)
		temp_file_dict = {}	#dizionario di corrispondenza file - filetemp
		table = [] #lista di corrispondenze files - filestemp	
		temp_dir = tempfile.mkdtemp(prefix="PLAIN") #Creo una cartella temporanea PLAINxxx che conterra tutti i file decifrati
		temp_file_dict['Temp plaintext dir'] = temp_dir
		self.set_temp_dir(temp_dir) #salvo la path della dir temporanea per poi poterla eliminare in del_trace
		for x in int_files: #Per ogni file .dec nel mounpoint, lo leggo, lo copio in un file temporaneo e lo elimino
			with open((path+x),"rb") as fr:				
				data = fr.read()
			temp = tempfile.NamedTemporaryFile(mode='w+b',delete=False, dir=temp_dir) #Creo un file temporaneo per ogni .dec
			temp.write(data) #ci scrivo il contenuto del .dec
			temp_file_dict['ciphertext'] = (path+x).replace(".dec","") #ne tengo traccia nella tabella delle corrispondenze
			temp_file_dict['plaintext'] = temp.name #ne tengo traccia nella tabella delle corrispondenze
			
			tablepath="/home/matteo/Desktop/corrTable" #Definisco dove mettero la tabella delle corrispondenze
			
			exTempDict = {'exTempDict':temp_file_dict}
			#Scrivo la tabella di corrispondere tra ciphertext nel MP e file temporanei nel /tmp e la metto in tablepath
			self.set_corrtable(tablepath)
			with open(tablepath,"a") as ftable: #creo la tabella delle corrispondenze
				ftable.write(json.dumps(exTempDict))
				#ftable.write("\n")
			self.delete_file(path+x) #elimino i plaintext dal mountpoint
			
		print("All files have been decrypted and are temporaneous files check the correspondace table: \n")
		self.print_table() 
		print("\n \nTo unmount, kill Passthrough.py process")
	
	def del_trace(self,path):
		print("Mountpoint unmounted \n")
		print("[*] deleting all traces \n")
		shutil.rmtree(self.tempdir)
		self.delete_file(self.corrtable)
		print("Traces deleted")
		
			
		
		
demo = msfs("/")
mppath = "/mnt/MP/" #mountpoin path
thread = threading.Thread(target=launchPass)
thread.daemon = True
thread.start()
time.sleep(2)
decripted = False

while(thread.is_alive()):
	if(decripted == False):
		demo.temporize(mppath)
	decripted = True
	
demo.del_trace(mppath)









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

