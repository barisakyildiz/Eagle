import socket
from struct import *

class UDPScan:
    def __init__(self, target, hostip):
        self.hostip = hostip
        self.target = target
        self.open_ports = []

    def __repr__(self):
        return "UDP Scanner started for target: {}".format(self.target)
        
    def addport(self, port):
        self.open_ports.append(port)

    def isopen(self, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
            data = "lmao"
            s.sendto(data, (self.target, self.port))
            s.settimeout(0)
            print((s.recvfrom(1024)))
            self.addport(port)
        except Exception as e:
            print("An Exception Occured >> {}".format(e))


