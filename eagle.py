import socket
from tools import timefunc
import subnetting
import argparse
from ScanTypes import TCPScans
from ScanTypes import TCPGrabService
from ScanTypes import UDPScans

@timefunc # Imported function for time
def main():
    prsr = argparse.ArgumentParser(description = "Network Scanner by Barış Akyıldız",
                                  formatter_class = argparse.RawTextHelpFormatter)
    prsr.add_argument("-t", "--target", help = "Target's IP address or URL", required = True)
    prsr.add_argument("-p", "--portrange", help = "Desired port range of the scan with the format of 'x-y' (Default: Most commonly used 1000 ports)")
    prsr.add_argument("-st", "--scantype", help = "Scan Type:\n\
        (1) TCP Connect Scan\n\
        (2) UDP Port Scan\n\
        (3) TCP Syn Port Scan\n")
    args = prsr.parse_args()

    hostname = socket.gethostname()
    hostip = socket.gethostbyname(hostname)
    if(str(args.target))[-1] == "/" or (str(args.target))[-2] == "/" or (str(args.target))[-3] == "/":
        ipadrrList = str(args.target).split("/")
        ipadrr = ipadrrList[0]
        subnet = ipadrrList[1]
        flag = 1
    else:
        ipadrr = str(args.target)
        flag = 0
    if args.portrange:
        if args.scantype == "1":
            if flag == 0:
                portrangelist = str(args.portrange).split("-")
                lowerport = int(portrangelist[0])
                higherport = int(portrangelist[1])
                TCPScanner = TCPScans.TCPConnect(ipadrr); TCPScanner.scanrange(lowerport, higherport)
                print(TCPScanner.__repr__())
                for port in TCPScanner.open_ports:
                    try:
                        grabber = TCPGrabService.Grabservice(ipadrr, port)
                        print('Port {} is open ---> {}'.format(port, grabber.read()))
                        grabber.close()
                    except Exception as e:
                        print('Error on scanning port: {} >> {}'.format(port, e))
                        grabber.close()
            else:
                portrangelist = str(args.portrange).split("-")
                lowerport = int(portrangelist[0])
                higherport = int(portrangelist[1])
                subnetClass = subnetting.Subnetting(args.target)
                networkArray = subnetClass.subnet()
                for ip in networkArray:
                    TCPScanner = TCPScans.TCPConnect(ip) 
                    TCPScanner.scanrange(lowerport, higherport)
                    print(TCPScanner.__repr__())#yukardaki try excepti aktar
                    for port in TCPScanner.open_ports:
                        try:
                            grabber = TCPGrabService.Grabservice(ip, port)
                            print('Port {} is open ---> {}'.format(port, grabber.read()))
                            grabber.close()
                        except Exception as e:
                            print('Error on scanning port: {} >> {}'.format(port, e))
                            grabber.close()
        elif args.scantype == "3":
            if flag == 0:
                portrangelist = str(args.portrange).split("-")
                lowerport = int(portrangelist[0])
                higherport = int(portrangelist[1])
                TCPSyn = TCPScans.TCPSYN(ipadrr, hostip); print(TCPSyn.__repr__()); TCPSyn.scanrange(lowerport, higherport)
                for port in TCPSyn.open_ports:
                    try:
                        print('Port {} is open and running'.format(port))
                    except Exception as e:
                        print('Error on scanning port: {} >> {}'.format(port, e))
            else:
                portrangelist = str(args.portrange).split("-")
                lowerport = int(portrangelist[0])
                higherport = int(portrangelist[1])
                subnetClass = subnetting.Subnetting(args.target)
                networkArray = subnetClass.subnet()
                for ip in networkArray:
                    TCPSyn = TCPScans.TCPSYN(ip, hostip); print(TCPSyn.__repr__()); TCPSyn.scanrange(lowerport, higherport)
                    for port in TCPSyn.open_ports:
                        try:
                            print('Port {} is open and running'.format(port))
                        except Exception as e:
                            print('Error on scanning port: {} >> {}'.format(port, e))

        elif args.scantype == "2":
            if flag == 0:
                portrangelist = str(args.portrange).split("-")
                lowerport = int(portrangelist[0])
                higherport = int(portrangelist[1])
                UDPScanner = UDPScans.UDPScan(ipadrr, hostip); print(UDPScanner.__repr__()); UDPScanner.scanrange(lowerport, higherport)
                for port in UDPScanner.open_ports:
                    try:
                        print('Port {} is open and running'.format(port))
                    except Exception as e:
                        print('Error on scanning port: {} >> {}'.format(port, e))
            else:
                portrangelist = str(args.portrange).split("-")
                lowerport = int(portrangelist[0])
                higherport = int(portrangelist[1])
                subnetClass = subnetting.Subnetting(args.target)
                networkArray = subnetClass.subnet()
                for ip in networkArray:
                    UDPScanner = UDPScans.UDPScan(ip, hostip); print(UDPScanner.__repr__()); UDPScanner.scanrange(lowerport, higherport)
                    for port in UDPScanner.open_ports:
                        try:
                            print('Port {} is open and running'.format(port))
                        except Exception as e:
                            print('Error on scanning port: {} >> {}'.format(port, e))
    else:
        if args.scantype == "1":
            if flag == 0:
                TCPScanner = TCPScans.TCPConnect(ipadrr); TCPScanner.scanfunc()
                print(TCPScanner.__repr__())
                for port in TCPScanner.open_ports:
                    try:
                        grabber = TCPGrabService.Grabservice(ipadrr, port)
                        print('Port {} is open ---> {}'.format(port, grabber.read()))
                        grabber.close()
                    except Exception as e:
                        print('Error on scanning port: {} >> {}'.format(port, e))
                        grabber.close()
            else:
                subnetClass = subnetting.Subnetting(args.target)
                networkArray = subnetClass.subnet()
                for ip in networkArray:
                    TCPScanner = TCPScans.TCPConnect(ip); TCPScanner.scanfunc()
                    print(TCPScanner.__repr__())
                    for port in TCPScanner.open_ports:
                        try:
                            grabber = TCPGrabService.Grabservice(ip, port)
                            print('Port {} is open ---> {}'.format(port, grabber.read()))
                            grabber.close()
                        except Exception as e:
                            print('Error on scanning port: {} >> {}'.format(port, e))
                            grabber.close()
        elif args.scantype == "3":
            if flag == 0:
                TCPSyn = TCPScans.TCPSYN(ipadrr, hostip); print(TCPSyn.__repr__()); TCPSyn.scanfunc()
                for port in TCPSyn.open_ports:
                    try:
                        print('Port {} is open and running'.format(port))
                    except Exception as e:
                        print('Error on scanning port: {} >> {}'.format(port, e))
            else:
                subnetClass = subnetting.Subnetting(args.target)
                networkArray = subnetClass.subnet()
                for ip in networkArray:
                    TCPSyn = TCPScans.TCPSYN(ip, hostip); 
                    print(TCPSyn.__repr__()); 
                    TCPSyn.scanfunc()
                    for port in TCPSyn.open_ports:
                        try:
                            print('Port {} is open and running'.format(port))
                        except Exception as e:
                            print('Error on scanning port: {} >> {}'.format(port, e))
        elif args.scantype == "2":
            if flag == 0:
                UDPScanner = UDPScans.UDPScan(ipadrr, hostip); print(UDPScanner.__repr__()); UDPScanner.scanfunc()
                for port in UDPScanner.open_ports:
                    try:
                        print('Port {} is open and running'.format(port))
                    except Exception as e:
                        print('Error on scanning port: {} >> {}'.format(port, e))
            else:
                subnetClass = subnetting.Subnetting(args.target)
                networkArray = subnetClass.subnet()
                for ip in networkArray:
                    UDPScanner = UDPScans.UDPScan(ip, hostip); print(UDPScanner.__repr__()); UDPScanner.scanfunc()
                    for port in UDPScanner.open_ports:
                        try:
                            print('Port {} is open and running'.format(port))
                        except Exception as e:
                            print('Error on scanning port: {} >> {}'.format(port, e))
                    
    

if __name__ == '__main__':
    main()
