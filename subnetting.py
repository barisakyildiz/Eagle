class Subnetting:
    def __init__(self, target, subnetRange):
        self.target = target
        self.subnetRange = subnetRange
        self.targetParts = target.split(".")
        self.subnetDict = {
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
        self.maskParts = (self.subnetDict[str(self.subnetRange)]).split(".")
    
    def bitwise(self):
        anded = int(self.targetParts[0]) & int(self.maskParts[3])
        print("{} and {}".format(self.targetParts, self.maskParts))
        return anded

def main():
    testClass = Subnetting("192.168.1.34", "24")
    print("{} is AND --> {}".format(testClass.targetParts[3], testClass.bitwise()))

if __name__ == '__main__':
    main()