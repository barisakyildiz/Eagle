import ipaddress

class Subnetting:
    def __init__(self, target):
        self.target = target
    
    def subnet(self):
        ips = ipaddress.ip_network(self.target)
        networkList = list(ips.hosts())
        self.networkArray = []
        for i in range(len(networkList)):
            self.networkArray.append(str(networkList[i]))
        return self.networkArray


def main():
    testClass = Subnetting("10.10.0.0/16")
    print(testClass.subnet())

if __name__ == '__main__':
    main()