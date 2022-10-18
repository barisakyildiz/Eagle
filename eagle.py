import socket
from tools import timefunc
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
    else:
        ipadrr = str(args.target)
    subnetDict = {
        "8" : "255.0.0.0",
        "16" : "255.255.0.0",
        "24" : "255.255.255.0",
        "32" : "255.255.255.255",
        "0" : "0.0.0.0",
        "1" : "128.0.0.0",
        "2" : "192.0.0.0",
        "3" : "224.0.0.0",
        "4" : "240.0.0.0",
        "5" : "248.0.0.0",
        "6" : "252.0.0.0",
        "7" : "254.0.0.0",
        "8" : "255.0.0.0",
        "9" : "255.128.0.0",
        "10" : "255.192.0.0",
        "11" : "255.224.0.0",
        "12" : "255.240.0.0",
        "13" : "255.248.0.0",
        "14" : "255.252.0.0",
        "15" : "255.254.0.0",
        "17" : "255.255.128.0",
        "18" : "255.255.192.0",
        "19" : "255.255.224.0",
        "20" : "255.255.240.0",
        "21" : "255.255.248.0",
        "22" : "255.255.252.0",
        "23" : "255.255.254.0",
        "25" : "255.255.255.128",
        "26" : "255.255.255.192",
        "27" : "255.255.255.224",
        "28" : "255.255.255.240",
        "29" : "255.255.255.248",
        "30" : "255.255.255.252",
        "31" : "255.255.255.254",
        "32" : "255.255.255.255"
    }
    if args.portrange:
        if args.scantype == "1":
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
        elif args.scantype == "3":
            portrangelist = str(args.portrange).split("-")
            lowerport = int(portrangelist[0])
            higherport = int(portrangelist[1])
            TCPSyn = TCPScans.TCPSYN(ipadrr, hostip); print(TCPSyn.__repr__()); TCPSyn.scanrange(lowerport, higherport)
            for port in TCPSyn.open_ports:
                try:
                    print('Port {} is open and running'.format(port))
                except Exception as e:
                    print('Error on scanning port: {} >> {}'.format(port, e))
        elif args.scantype == "2":
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
        if args.scantype == "1":
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
        elif args.scantype == "3":
            TCPSyn = TCPScans.TCPSYN(ipadrr, hostip); print(TCPSyn.__repr__()); TCPSyn.scanfunc()
            for port in TCPSyn.open_ports:
                try:
                    print('Port {} is open and running'.format(port))
                except Exception as e:
                    print('Error on scanning port: {} >> {}'.format(port, e))
        elif args.scantype == "2":
            UDPScanner = UDPScans.UDPScan(ipadrr, hostip); print(UDPScanner.__repr__()); UDPScanner.scanfunc()
            for port in UDPScanner.open_ports:
                try:
                    print('Port {} is open and running'.format(port))
                except Exception as e:
                    print('Error on scanning port: {} >> {}'.format(port, e))
    

if __name__ == '__main__':
    main()
