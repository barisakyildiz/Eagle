import socket

class Grabservice: # IPV4 TCP Connect Service Grabber
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.settimeout(0.3)
        self.s.connect((self.ip, self.port))
    
    def read(self, length = 1024):
        return self.s.recv(length)
    
    def close(self):
        self.s.close()


def main():
    pass

if __name__ == '__main__':
    main()