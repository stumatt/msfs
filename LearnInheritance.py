class Product:
	
	def __init__(self):
		self.name = "John"
		self.description = 'Its Awesome'
		self.price = 700
		
	def display(self):  #instance method
		print(self.name)
		print(self.price)
		print(self.description)
		
p1 = Product()
print(p1.name)
print(p1.price)
print(p1.description)

p1.display()

####################################################################
####################################################################

class Course:
	def __init__(self,name,ratings):
		self.name = name
		self.ratings  = ratings
	
	def average(self):
		numberOfRatings = len(self.ratings)
		average = sum(self.ratings)/numberOfRatings
		print("Average Ratings for", self.name, "is" ,average)
	
c1 = Course("Python Course",[1,2,3,4,5])
print(c1.name)
print(c1.ratings)
c1.average()

c2 = Course("Java Course",[1,2,3,4,5])
print(c2.name)
print(c2.ratings)
c2.average()

####################################################################
####################################################################

class Programmer:
	
	def setName(self,name):
		self.name = name
		
	def getName(self):
		return self.name
	
	def setSalary(self,sal):
		self.salary = sal
		
	def getSalary(self):
		return self.salary
	
	def setTechnologies(self,techs):
		self.technologies = techs
		
	def getTechnologies(self):
		return self.technologies
	
p1 = Programmer()
p1.setName("Sammy")
p1.setSalary(1000)
p1.setTechnologies(["Java","Spring","Python"])
print(p1.getName(),p1.getSalary(),p1.getTechnologies())

####################################################################
####################################################################

class Student:
	major="CSE" #Static field
	numberOfObject = 0
	
	def __init__(self,rollno,name):
		Student.numberOfObject += 1
		self.rollno=rollno
		self.name=name
		
	def displayCount(): #Static metod
		print(Student.numberOfObject)
		
s1 = Student(1,"John")
s2 = Student(2,"Bill")
print(s1.major,s2.major)
print(Student.major) #Static field are invoked directly by class
Student.displayCount() #Static method are invoked directly by class

####################################################################
####################################################################

class Car: #outer class
	def __init__(self,make,year):
		self.make=make
		self.year=year
	
	class Engine: #inner class
		def __init__(self,number):
			self.number=number
		def start(self):
			print("Engine started")
		
c = Car("BMW",2017)
e = c.Engine(123)
e.start()

####################################################################
####################################################################

#ENCAPSULATION 
#It's about protecting the properties and the functionality of an objet from other objetcs.
#Creating a capsule contening all field and method about an object

class Students:
	def __init__(self):
		self.id=123;
		self.name="john"
		self.__surname="derry"
	
	def display(self):
		print(self.__surname)
		
s = Students()
print(s.id,s.name) #this fields are public, in fact they are accessible
#print(s.__surname) #AttributeError: 'Students' object has no attribute '__surname'
s.display() #through display method the private field too are accessible
#name mangling sintax
print(s._Students__surname) #alternative call to access a private field surname

#IMPLEMENTING ENCAPSULATION

class Worker:
	def setId(self,id):
		self.id = id
	def getId(self):
		return self.id
w = Worker()
w.setId("1047002")
print(w.getId())
print(w.id)

##################################

class Patient:
	def setId(self,id):
		self.id=id
	def getId(self):
		return self.id
	def setName(self,name):
		self.name=name
	def getName(self):
		return self.name
	def setSsn(self,ssn):
		self.ssn=ssn
	def getSsn(self):
		return self.ssn
p1 = Patient()
p2 = Patient()
p1.setId(123)
p1.setName("marc")
p1.setSsn("13124edwe23")
print(p1.getId(),p1.getName(),p1.getSsn())
p2.setId(12283693)
p2.setName("marcolain")
p2.setSsn("13kldhiowdwe23")
print(p2.getId(),p2.getName(),p2.getSsn())


#INHERITANCE
#It's the process of defining a new object with the help of an existing object

class BMW:
	def __init__(self,make,model,year):
		self.make=make
		self.model=model
		self.year=year
	def start(self):
		print("Starting the car")
	def stop(self):
		print("Stopping the car")

#OVERRIDING
#The mother class provides start() method, the sub-classes can implements this method with differently functionality

class ThreeSeries(BMW):
	def __init__(self,cruiseControlEnabled,make,model,year):
		BMW.__init__(self,make,model,year)
		self.cruiseControlEnabled = cruiseControlEnabled;
		
	def display(self):
			print(self.cruiseControlEnabled,self.make,self.model,self.year)

	def start(self):
		print("Button Start")
		
		
class FiveSeries(BMW):
	def __init__(self,parkingAssistEnabled,make,model,year):
		super().__init__(make,model,year)
		self.parkingAssistEnabled = parkingAssistEnabled;
		
	def start(self):
		super().start()
		print("Button Start")
		
S3= ThreeSeries("true" ,"BMW","328i","2018")
print(S3.cruiseControlEnabled)

S5= FiveSeries("true","BMW","3928i","2008")
print(S5.parkingAssistEnabled)

S5.stop()
S3.display()
#OVERRIDING
S3.start()
S5.start()

#POLYMORPHISM 
#POLY means multi and MORPHIC means shapes in the world of oop, shapes are behavior of object

#polymorphism is implementable by:
#1. Duck Typing
#it isn't a particular feature of program language, but come for free by the dinamicity of python
class Duck:
	def talk(self):
		print("quack")
class Human:
	def talk(self):
		print("hello")
def callTalk(obj):
	obj.talk()

d = Duck()
h = Human()
callTalk(d)
callTalk(h)
		
#2. Duck Typing with Depency Injection
#Injection is nothing but simply injecting an object into an other object as required

class Flight:
	def __init__(self,engine):
		self.engine = engine
	def startEngine(self):
		self.engine.start() #Where is this method?
		
class AirbusEngine:
	def start(self):
		print("Starting Airbus engine")
class BoingEngine:
	def start(self):
		print("Starting Boing engine")
		
ae = AirbusEngine()
f1 =Flight(ae)
f1.startEngine()

be = BoingEngine()
f2=Flight(be)
f2.startEngine()
		

#3. Using + operator



	
	
