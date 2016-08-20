import time
import sys
import os

#TODO refactore paths
sys.path.append(os.path.abspath('../utils'))
sys.path.append(os.path.abspath('../models'))
sys.path.append(os.path.abspath('.'))

from senz_parser import *
from crypto_utils import *
from config import *
if GPIO:
   import RPi.GPIO as GPIO

class SenzHandler():
    """
    Handler incoming senz messages from here. We are dealing with following
    senz types
        1. GET
        2. PUT
        3. SHARE
        4. DATA

    According to the senz type different operations need to be carry out
    """
    def __init__(self, transport):
        """
        Initilize udp transport from here. We can use transport to send message
        to udp socket

        Args:
            trnsport - twisted transport instance
        """
        self.transport = transport

    def reghistration(self):



    def handleSenz(self, senz):
        """
        Handle differennt types of senz from here. This function will be called
        asynchronously. Whenc senz message receives this function will be
        called by twisted thread(thread safe mode via twisted library)
        """
        print 'senz received %s' % senz.type
        print 'senz sender %s' % senz.sender
        print 'senz receiver %s' % senz.receiver

        data=senz.attributes
        qtime=""
        if "time" in senz.attributes.keys(): qtime=data["time"]
        print data
        if senz.type=='PUT':
            get={}
            for i in data:
                #print i," in senz attributes"
                if i in sws.keys() and data[i]!="":
                    print i,"-",data[i]
                    status=0
                    if data[i]=="on": status=1
                    if GPIO: GPIO.output(sws[i],status)
                    #print "*** ",sws[i]," ",status
		    get[i]=data[i]
         

            self.send_data("PutDone",get,senz.sender,qtime,senz.receiver)
                  
        if senz.type=='GET':
            print 'GET  message'

            if "photo" in data:
                print "Creeate photo senze"
                self.send_photo(senz.sender,qtime,senz.receiver)
            else:
                get={} 
                for i in data:
                    if i in sws.keys():
                       get[i]='off'
                       if GPIO and GPIO.input(sws[i])==1: get[i]='on'
                self.send_data("GetResponse",get,senz.sender,qtime,senz.receiver)        

        if senz.type == 'DATA':
            print senz.attributes['msg']
            if senz.attributes['msg'] == 'UserCreated':
                # SHARE gpio senz from here
                self.share_attribute()
                # TODO: set configureation to READY state

    def share_attribute(self):
        receiver = userName
        sender = homeName
        swlist=""
        if GPIO:
           for sw in gpioPorts:
               swlist+="#"+sw[0]+" "
        senz = "SHARE #homez #photo %s#time %s @%s ^%s" %(swlist,time.time(), receiver, sender)
        signed_senz = sign_senz(senz)
        self.transport.write(signed_senz)
        print signed_senz

    def postHandle(self, arg):
        """
        After handling senz message this function will be called. Basically
        this is a call back funcion
        """
        # self.transport.write('senz')
        print "handled"
 

    def send_photo(self,receiver,qtime,sender):
        senz="DATA #photo "
        print "Creeate photo senze"
        senz=senz+"IMAGE"
        if qtime!="":
           senz = senz+" #time %s @%s ^%s" %(qtime,receiver, sender)
        else:
           senz = senz+" #time %s @%s ^%s" %(time.time(),receiver, sender)
        print senz
        signed_senz = sign_senz(senz)
        self.transport.write(signed_senz)


    def send_data(self,msg,data,receiver,qtime,sender):
        #receiver = 'userpi'
        #sender = 'homepi'
        senz="DATA #msg "+msg
       
        for i in data:
            senz=senz+" #"+i+" "+str(data[i])

        if qtime!="":
           senz = senz+" #time %s @%s ^%s" %(qtime,receiver, sender)
        else:
           senz = senz+" #time %s @%s ^%s" %(time.time(),receiver, sender)
        print senz
        signed_senz = sign_senz(senz)
        self.transport.write(signed_senz)
