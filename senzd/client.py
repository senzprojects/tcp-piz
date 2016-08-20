
# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.


"""
An example client. Run simpleserv.py first before running this.
"""
from __future__ import print_function

from twisted.internet import reactor, protocol

import datetime

import socket
import time
import sys
import thread
import os.path


lib_path = os.path.abspath('../utils')
sys.path.append(lib_path)
from myParser import *
from myCrypto import *
import hashlib
#from PIL import Image

lib_path1 = os.path.abspath('../')
sys.path.append(lib_path1)
from config import *

serverPubKey = ""
aesKeys = {}

class SENZClient(protocol.Protocol):

    def readSenze(self):
        response = raw_input("Enter your Senze:")
        self.sendData(response)

    def startProtocol(self):
        global state
        print(state)
        if state == 'INITIAL':
            #If system is at the initial state, it will send the device creation Senz
            self.register()
        else:
            reactor.callLater(1, self.sendPing,5)
            reactor.callLater(3, self.readSenze)

    def register(self):
        global server
        cry = myCrypto(name=device)
        senze = 'SHARE #pubkey %s @%s' % (pubkey, server)
        senze = cry.signSENZE(senze)
        self.transport.write(senze)

    def registrationDone(self,sensors,data,parser):
        global device
        global serverPubkey
        cry = myCrypto(name=device)

        if 'msg' in sensors and 'pubkey' in sensors :
           serverPubkey = data['pubkey']
           if cry.verifySENZE(parser,serverPubkey):
              if 'REG_DONE' in data['msg'] or 'REG_ALR' in data['msg']:
                  # Creating the .devicename file and store the device name
                  # public key of mysensor server
                  f = open(".devicename", 'w')
                  f.write(device + '\n')
                  pubkey = data['pubkey']
                  print (pubkey)
                  f.write(pubkey + '\n')
                  f.close()
                  print (device + " was created at the server.")
                  print ("You should execute the program again with READY state.")

              elif 'REG_ALR' in data['msg']:
                  print ("This user name is already registered")
                  print ("You should execute the program again with READY state.")

              else:
                  print ("This user name is already already taken")
                  print ("You can try it again with different username")

              print ("The system halted!")
              reactor.stop()

           else:
              print ("SENZE Verification failed")
        else:
            print ("Unknown SENZE type")

    #Let's send a ping to keep open the active
    def sendPing(self, delay):
        global server
        senze = 'PING @%s' % (server)
        self.sendData(senze)
        reactor.callLater(delay, self.sendPing, delay=delay)

    def sendData(self, senze):
        cry = myCrypto(name=device)
        senze = cry.signSENZE(senze)
        print(senze)
        self.transport.write(senze)

    #Senze response should be built as follows by calling the functions in the driver class
    def sendDataSenze(self, sensors, data, recipient):
        global device
        global aesKeys

        response = 'DATA'
        driver = myDriver()
        cry = myCrypto(device)

        for sensor in sensors:
            #If AES key is requested
            if "key" == sensor:
                aeskey = ""
                #Generate AES Key
                if cry.generateAES(driver.readTime()):
                    aeskey = cry.key
                    #Save AES key
                    aesKeys[recipient] = aeskey
                    #AES key is encrypted by the recipient public key
                    rep = myCrypto(recipient)
                    encKey = rep.encryptRSA(b64encode(aeskey))
                response = '%s #key %s' % (response, encKey)

            #If time is requested
            elif "time" == sensor:
                response = '%s #time %s' % (response, driver.readTime())
            else:
                response = '%s #%s NULL' % (response, sensor)

        response = "%s @%s" % (response, recipient)
        self.sendData(senze=response)

    def handleServerResponse(self, senze):
        sender = senze.getSender()
        data = senze.getData()
        sensors = senze.getSensors()
        cmd = senze.getCmd()

        if cmd == "DATA":
            if 'msg' in sensors and 'UserRemoved' in data['msg']:
                cry = myCrypto(device)
                try:
                    os.remove(".devicename")
                    os.remove(cry.pubKeyLoc)
                    os.remove(cry.privKeyLoc)
                    print ("Device was successfully removed")
                except OSError:
                    print ("Cannot remove user configuration files")
                    reactor.stop()

            elif 'pubkey' in sensors and data['pubkey'] != "" and 'name' in sensors and data['name'] != "":
                recipient = myCrypto(data['name'])
                if recipient.saveRSAPubKey(data['pubkey']):
                    print ("Public key=> " + data['pubkey'] + " Saved.")
                else:
                    print ("Error: Saving the public key.")
        elif cmd == "GET":
            print ("This should be implemented")
        elif cmd == "PUT":
            print ("This should be implemented")
        else:
            print ("Unknown Command")


    def handleDeviceResponse(self, senze):
        global device
        global aesKeys
        sender = senze.getSender()
        data = senze.getData()
        sensors = senze.getSensors()
        cmd = senze.getCmd()
        if cmd == "DATA":
            for sensor in sensors:
                if sensor in data.keys():
                    print (sensor + "=>" + data[sensor])

            #Received and saved the AES key
            if 'key' in sensors and data['key'] != "":
                #Key need to be decrypted by using the private key
                cry = myCrypto(device)
                dec = cry.decryptRSA(data['key'])
                #line
                aesKeys[sender] = b64decode(dec)

            #Decrypt and show the gps data
        elif cmd == "SHARE":
            print ("This should be implemented")

        elif cmd == "UNSHAR":
            print ("This should be implemented")

        elif cmd == "GET":
            #If GET Senze was received. The device must handle it.
            reactor.callLater(1,self.sendDataSenze, sensors=sensors, data=data, recipient=sender)

        elif cmd == "PUT":
            reactor.callLater(1, self.handlePUTSenze, sensors=sensors, data=data, recipient=sender)
        else:
            print ("Unknown command")


    def connectionMade(self):
        self.startProtocol()

    #RECEIVED A RESPONSE
    def dataReceived(self, data):
        #data=data.replace('\n','')
        #data=data.replace('\r','')
        print("Server said:", data)

        global device
        global server
        parser = myParser(data)
        recipients = parser.getUsers()
        sender = parser.getSender()
        signature = parser.getSignature()
        data = parser.getData()
        sensors = parser.getSensors()
        cmd = parser.getCmd()

        validQuery = False
        cry = myCrypto(device)

        if state == "INITIAL" and sender==server:
            self.registrationDone(sensors,data,parser)

        elif state == "READY":
            if serverPubkey != "" and sender == server:
                if cry.verifySENZE(parser,serverPubkey):
                    self.handleServerResponse(parser)
                else:
                    print ("SENZE Verification failed")
            else:
                if sender != "":
                    recipient = myCrypto(sender)
                    if os.path.isfile(recipient.pubKeyLoc):
                        pub = recipient.loadRSAPubKey()
                    else:
                        pub = ""
                    if pub != "" and cry.verifySENZE(parser, pub):
                        print ("SENZE Verified")
                        self.handleDeviceResponse(parser)
                    else:
                        print ("SENZE Verification failed")
        else:
            print ("Unknown Sate")

        reactor.callLater(1, self.readSenze)


def connectionLost(self, reason):
        print("connection lost")

class TCPFactory(protocol.ClientFactory):
    protocol = SENZClient

    def clientConnectionFailed(self, connector, reason):
        print("Connection failed - goodbye!")
        #reactor.stop()
    
    def clientConnectionLost(self, connector, reason):
        print("Connection lost - goodbye!")
        #reactor.stop()


def init():
    #cam=myCamDriver()
    global device
    global pubkey
    global serverPubkey
    global state

    #If .device name is not there, we will read the device name from keyboard
    #else we will get it from .devicename file
    try:
        if not os.path.isfile(".devicename"):
            device = raw_input("Enter the device name: ")
            # Account need to be created at the server
            state = 'INITIAL'
        else:
            #The device name and server public key will be read form the .devicename file
            f = open(".devicename", "r")
            device = f.readline().rstrip("\n")
            serverPubkey = f.readline().rstrip("\n")
            print(serverPubkey)
            state = 'READY'
    except:
        print ("ERRER: Cannot access the device name file.")
        raise SystemExit

    #Here we will generate public and private keys for the device
    #These keys will be used to perform authentication and key exchange
    try:
        cry = myCrypto(name=device)
        #If keys are not available yet
        if not os.path.isfile(cry.pubKeyLoc):
            # Generate or loads an RSA keypair with an exponent of 65537 in PEM format
            # Private key and public key was saved in the .devicenamePriveKey and .devicenamePubKey files
            cry.generateRSA(bits=1024)
        pubkey = cry.loadRSAPubKey()
    except:
        print("ERRER: Cannot genereate private/public keys for the device.")
        raise SystemExit
    print (pubkey)

    #Check the network connectivity.
    #check_connectivity(ServerName)


    
# this connects the protocol to a server running on port 7070
def main():
    global hostName
    global port
    f = TCPFactory()
    print(hostName)
    print(port)
    reactor.connectTCP(hostName,port, f)
    reactor.run()

# this only runs if the module was *not* imported
if __name__ == '__main__':
    init()
    main()
