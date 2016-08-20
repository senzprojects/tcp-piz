# senzc_RPI
Raspberry Pi module Senz Client for Smart home Apllication 

Directry Structure

▾ handlers/

	__init__.py
	
	senz_handler.py
	
	senz_handler.pyc
	
▾ models/

    __init__.py 
    
    senz.py
    
    senz.pyc
    
▾ senzc/
    __init__.py
    
    client.py
    
    senzc.py
    
    senzc.pyc
    
▸ utils/

	 __init__.py
  
	 config.cfg
	 
	 config.py
  
  	config.pyc
  
README.md


Set UserNames :

	Goto Application home and edit client names of config.cfg file.
	'homeName' is your smart home name, your smart home register for 
	mySensors server with this name.
	'userName' is the name which used to register for Android Senz-Service.
	when multiple users controls the same home, you can add those users under clients.

How to run

	Application can run by running client.py file which was in directory called senzc from 
	application home with usper user permissions.
	-sudo python senzc/client.py-

Customize

	All senz messages are handled by handlers.py file which was in 	handlers directory.


	
