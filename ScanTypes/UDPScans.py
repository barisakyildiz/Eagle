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
    
    def writetofile(self, filepath):
        openport = map(str, self.open_ports)
        with open(filepath, 'w') as f:
            f.write('\n'.join(openport))

    def scanrange(self, lowerport, higherport):
        for port in range(lowerport, higherport + 1):
            self.isopen(port)
    
    def scanfunc(self):
        portslist = [2,3,7,9,13,17,19,20,21,22,23,37,38,42,49,53,67,68,69,80,88,111,112,
        113,120,123,135,136,137,138,139,158,161,162,177,192,199,207,217,363,389,402,407,
        427,434,443,445,464,497,500,502,512,513,514,515,517,518,520,539,559,593,623,626,
        631,639,643,657,664,682,683,684,685,686,687,688,689,764,767,772,773,774,775,776,
        780,781,782,786,789,800,814,826,829,838,902,903,944,959,965,983,989,990,996,997,
        998,999,1000,1001,1007,1008,1012,1013,1014,1019,1020,1021,1022,1023,1024,1025,
        1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,
        1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1053,1054,1055,1056,1057,1058,
        1059,1060,1064,1065,1066,1067,1068,1069,1070,1072,1080,1081,1087,1088,1090,1100,
        1101,1105,1124,1200,1214,1234,1346,1419,1433,1434,1455,1457,1484,1485,1524,1645,
        1646,1701,1718,1719,1761,1782,1804,1812,1813,1885,1886,1900,1901,1993,2000,2002,
        2048,2049,2051,2148,2160,2161,2222,2223,2343,2345,2362,2967,3052,3130,3283,3296,
        3343,3389,3401,3456,3457,3659,3664,3702,3703,4000,4008,4045,4444,4500,4666,4672,
        5000,5001,5002,5003,5010,5050,5060,5093,5351,5353,5355,5500,5555,5632,6000,6001,
        6002,6004,6050,6346,6347,6970,6971,7000,7938,8000,8001,8010,8181,8193,8900,9000,
        9001,9020,9103,9199,9200,9370,9876,9877,9950,10000,10080,11487,16086,16402,16420,
        16430,16433,16449,16498,16503,16545,16548,16573,16674,16680,16697,16700,16708,
        16711,16739,16766,16779,16786,16816,16829,16832,16838,16839,16862,16896,16912,
        16918,16919,16938,16939,16947,16948,16970,16972,16974,17006,17018,17077,17091,
        17101,17146,17184,17185,17205,17207,17219,17236,17237,17282,17302,17321,17331,
        17332,17338,17359,17417,17423,17424,17455,17459,17468,17487,17490,17494,17505,
        17533,17549,17573,17580,17585,17592,17605,17615,17616,17629,17638,17663,17673,
        17674,17683,17726,17754,17762,17787,17814,17823,17824,17836,17845,17888,17939,
        17946,17989,18004,18081,18113,18134,18156,18228,18234,18250,18255,18258,18319,
        18331,18360,18373,18449,18485,18543,18582,18605,18617,18666,18669,18676,18683,
        18807,18818,18821,18830,18832,18835,18869,18883,18888,18958,18980,18985,18987,
        18991,18994,18996,19017,19022,19039,19047,19075,19096,19120,19130,19140,19141,
        19154,19161,19165,19181,19193,19197,19222,19227,19273,19283,19294,19315,19322,
        19332,19374,19415,19482,19489,19500,19503,19504,19541,19600,19605,19616,19624,
        19625,19632,19639,19647,19650,19660,19662,19663,19682,19683,19687,19695,19707,
        19717,19718,19719,19722,19728,19789,19792,19933,19935,19936,19956,19995,19998,
        20003,20004,20019,20031,20082,20117,20120,20126,20129,20146,20154,20164,20206,
        20217,20249,20262,20279,20288,20309,20313,20326,20359,20360,20366,20380,20389,
        20409,20411,20423,20424,20425,20445,20449,20464,20465,20518,20522,20525,20540,
        20560,20665,20678,20679,20710,20717,20742,20752,20762,20791,20817,20842,20848,
        20851,20865,20872,20876,20884,20919,21000,21016,21060,21083,21104,21111,21131,
        21167,21186,21206,21207,21212,21247,21261,21282,21298,21303,21318,21320,21333,
        21344,21354,21358,21360,21364,21366,21383,21405,21454,21468,21476,21514,21524,
        21525,21556,21566,21568,21576,21609,21621,21625,21644,21649,21655,21663,21674,
        21698,21702,21710,21742,21780,21784,21800,21803,21834,21842,21847,21868,21898,
        21902,21923,21948,21967,22029,22043,22045,22053,22055,22105,22109,22123,22124,
        22341,22692,22695,22739,22799,22846,22914,22986,22996,23040,23176,23354,23531,
        23557,23608,23679,23781,23965,23980,24007,24279,24511,24594,24606,24644,24854,
        24910,25003,25157,25240,25280,25337,25375,25462,25541,25546,25709,25931,26407,
        26415,26720,26872,26966,27015,27195,27444,27473,27482,27707,27892,27899,28122,
        28369,28465,28493,28543,28547,28641,28840,28973,29078,29243,29256,29810,29823,
        29977,30263,30303,30365,30544,30656,30697,30704,30718,30975,31059,31073,31109,
        31189,31195,31335,31337,31365,31625,31681,31731,31891,32345,32385,32528,32768,
        32769,32770,32771,32772,32773,32774,32775,32776,32777,32778,32779,32780,32798,
        32815,32818,32931,33030,33249,33281,33354,33355,33459,33717,33744,33866,33872,
        34038,34079,34125,34358,34422,34433,34555,34570,34577,34578,34579,34580,34758,
        34796,34855,34861,34862,34892,35438,35702,35777,35794,36108,36206,36384,36458,
        36489,36669,36778,36893,36945,37144,37212,37393,37444,37602,37761,37783,37813,
        37843,38037,38063,38293,38412,38498,38615,39213,39217,39632,39683,39714,39723,
        39888,40019,40116,40441,40539,40622,40708,40711,40724,40732,40805,40847,40866,
        40915,41058,41081,41308,41370,41446,41524,41638,41702,41774,41896,41967,41971,
        42056,42172,42313,42431,42434,42508,42557,42577,42627,42639,43094,43195,43370,
        43514,43686,43824,43967,44101,44160,44179,44185,44190,44253,44334,44508,44923,
        44946,44968,45247,45380,45441,45685,45722,45818,45928,46093,46532,46836,47624,
        47765,47772,47808,47915,47981,48078,48189,48255,48455,48489,48761,49152,49153,
        49154,49155,49156,49157,49158,49159,49160,49161,49162,49163,49165,49166,49167,
        49168,49169,49170,49171,49172,49173,49174,49175,49176,49177,49178,49179,49180,
        49181,49182,49184,49185,49186,49187,49188,49189,49190,49191,49192,49193,49194,
        49195,49196,49197,49198,49199,49200,49201,49202,49204,49205,49207,49208,49209,
        49210,49211,49212,49213,49214,49215,49216,49220,49222,49226,49259,49262,49306,
        49350,49360,49393,49396,49503,49640,49968,50099,50164,50497,50612,50708,50919,
        51255,51456,51554,51586,51690,51717,51905,51972,52144,52225,52503,53006,53037,
        53571,53589,53838,54094,54114,54281,54321,54711,54807,54925,55043,55544,55587,
        56141,57172,57409,57410,57813,57843,57958,57977,58002,58075,58178,58419,58631,
        58640,58797,59193,59207,59765,59846,60172,60381,60423,61024,61142,61319,61322,
        61370,61412,61481,61550,61685,61961,62154,62287,62575,62677,62699,62958,63420,
        63555,64080,64481,64513,64590,64727,65024]
        for port in portslist:
            self.isopen(port)
