import ipaddress
import socket
from tools import timefunc
import argparse
from ScanTypes import TCPScans
from ScanTypes import TCPGrabService

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

    ipadrr = str(args.target)
    if args.portrange:
        if args.scantype == "1":
            portrangelist = str(args.portrange).split("-")
            lowerport = int(portrangelist[0])
            higherport = int(portrangelist[1])
            TCPScanner = TCPScans.TCPConnect(ipadrr); TCPScanner.scanrange(lowerport, higherport)
            for port in TCPScanner.open_ports:
                try:
                    grabber = TCPGrabService.Grabservice(ipadrr, port)
                    print('Port {} is open ---> {}'.format(port, grabber.read()))
                    grabber.close()
                except Exception as e:
                    print('Error on scanning port: {} >> {}'.format(port, e))
                    grabber.close()
            del TCPScanner, grabber
    else:
        if args.scantype == "1":
            TCPScanner = TCPScans.TCPConnect(ipadrr); TCPScanner.scanfunc()
            for port in TCPScanner.open_ports:
                try:
                    grabber = TCPGrabService.Grabservice(ipadrr, port)
                    print('Port {} is open ---> {}'.format(port, grabber.read()))
                    grabber.close()
                except Exception as e:
                    print('Error on scanning port: {} >> {}'.format(port, e))
                    grabber.close()
            del TCPScanner, grabber
    

if __name__ == '__main__':
    main()