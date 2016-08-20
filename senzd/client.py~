from twisted.internet.protocol import DatagramProtocol
from twisted.internet.task import LoopingCall
from twisted.internet import reactor, threads

import socket
import time
import sys
import RPi.GPIO as GPIO
import os


#TODO refactore paths
sys.path.append(os.path.abspath('./utils'))
sys.path.append(os.path.abspath('./models'))
sys.path.append(os.path.abspath('./handlers'))
sys.path.append(os.path.abspath('.'))

print os.getcwd()
from config import *
from crypto_utils import *
from senz_handler import *
from senz import *


class SenzcProtocol(DatagramProtocol):
    """
    Protocol will connects to udp port(which server runs on). When packet(semz)
    comes to server we have to asynchornosly handle them. We are starting
    thread save twisted thread on GET, SHARE and PUT senz
    """
    def __init__(self, host, port):
        """
        initiliaze senz server host and port

        Args:
            host - server host
            port - server port
        """
        self.host = host
        self.port = port

    def startProtocol(self):
        """
        Call when twisted udp protocol starts, Few actions need to be done from
        here
            1. First need to connect to udp socket from here.
            2. Then need to share public key to server via SHARE senz
            3. Finall need to start looping call to send ping messages to
               server in every 30 mins
        """
        print '*** Client Started ***'
        self.transport.connect(self.host, self.port)

        # if state is INITIAL share public key on start
        if dstate=="INITIAL":
           self.share_pubkey()
        else:
           handler = SenzHandler(self.transport)
           handler.share_attribute()

        # start ping sender to send ping messages to server in everty 30 mins
        lc = LoopingCall(self.send_ping)
        lc.start(60)

    def stopProtocol(self):
        """
        Call when datagram protocol stops. Need to clear global connection if
        exits from here
        """
        print '*** Client Stopped ***'

    def datagramReceived(self, datagram, host):
        """
        Call when datagram recived, datagrams are senz messages in our scenario
        We have to handle receiveing senz from here. Senz handling part will be
        delegated to SenzHandler

        Args:
            datagra - senz message
            host - receving host
        """
        print 'datagram received %s' % datagram

        # handle receved datagram(senz)
        self.handle_datagram(datagram)

    def share_pubkey(self):
        """
        Send public key of the senzy to server via SHARE senz. We have to
        digitally senz the senz before sending to server.
        SHARE senz message would be like below

            SHARE
                #pubkey <pubkey>
                #time <time>
            @mysensors
            ^<sender> <digital signature>
        """
        # send pubkey to server via SHARE senz
        pubkey = get_pubkey()
        receiver = server
        sender = homeName
        senz = "SHARE #pubkey %s #time %s @%s ^%s" % \
                         (pubkey, time.time(), receiver, sender)
        signed_senz = sign_senz(senz)

        self.transport.write(signed_senz)

    def send_ping(self):
        """
        Send ping message to server in everty 30 minutes. The purpose of
        peroidc ping message is keeping the connection(NAT table entry).
        ping message would be like below

            DATA
                #time <time>
            @mysensors
            ^<sender> <digital signature>
        """
        # send ping message to server via DATA senz
        receiver = server
        sender =homeName
        senz = "DATA #time %s @%s ^%s" % \
                                    (time.time(), receiver, sender)
        signed_senz = sign_senz(senz)
        self.transport.write(signed_senz)

    def handle_datagram(self, datagram):
        """
        Handle receving senz from here, we have to do
            1. Parse the datagram and obtain senz
            2. We have to ignore ping messages from server
            3. We have to handler GET, SHARE, PUT senz messages via SenzHandler
        """
        if datagram == 'PING':
            # we ingnore ping messages
            print 'ping received'
        else:
            # parse senz first
            senz = parse(datagram)
            print "Datagram Recieved"
            # start threads for GET, PUT, DATA, SHARE senz
            handler = SenzHandler(self.transport)
            d = threads.deferToThread(handler.handleSenz, senz)
            d.addCallback(handler.postHandle)

def init_pi():
    GPIO.setwarnings(False)
    #GPIO.setmode(GPIO.BCM)
    GPIO.setmode(GPIO.BOARD)
    for sw in sws:
        GPIO.setup(sws[sw],GPIO.OUT)
    
    #GPIO.setwarnings(False)
    print "RaspberriPI initialized"
    for sw in sws:
        #print sws
        GPIO.output(sws[sw],0)
        time.sleep(2)
    
def init():
    """
    Init client certificates from here. All keys will be stored in .keys/
    directory in project root. We have to verify this content of that directory
    while initializing the keys
    """
    # init keys via crypto utils
    if dstate=="INITIAL":
       init_keys()
    init_pi()

def start():
    """
    Start upd senz protocol from here. It means connecting to senz server. We
    have to provide server host and port details form here.(read from config)
    """
   
    host = socket.gethostbyname(hostName)
    
    # start ptotocol
    protocol = SenzcProtocol(host, port)
    reactor.listenUDP(0, protocol)
    reactor.run()

if __name__ == '__main__':
    init()
    start()
