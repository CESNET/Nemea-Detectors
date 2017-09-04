#!/usr/bin/env python

import pytrap
import sys
import re
import yaml

class Blacklist(object):
    def __init__(self, config):
        """Create a blacklist instance from the list stored in file path"""
        self.ftype = config.get("filter_type", None)
        self.name = config.get("name", None)
        self.desc = config.get("description", None)
        self.path = config.get("file", None)

        if not self.name:
            raise KeyError("Mandatory key `name` was not found for the blacklist.")

        if not self.path:
            raise KeyError("Mandatory key `file` was not found for " + blname + " blacklist.")

    def __contains__(self, elem):
        raise Exception("Inherited class didn't implement __contains__()")

    def __str__(self):
        return self.ftype + " " + self.name + " from path " + self.path


class IPEntity(object):
    """This class represents one "rule" of blacklist.
    It can be an IP address(/range), pair of IP addresses(/ranges), ports.
    TODO link to documentation."""
    def __parse_ports(self, string):
        """Split string into int or tuple(int, int).
        String can be either one port or port range."""
        if not string:
            return None
        r = string.split("-")
        if len(r) == 1:
            return int(r[0])
        elif len(r) == 2:
            return (int(r[0]), int(r[1]))
        else:
            raise ValueError("Unexpected format of ports ({0}).".format(string))

    def __init__(self, string):
        self.ip = None
        self.srcip = None
        self.dstip = None
        self.dstport = None
        self.dstportrange = None
        self.srcport = None
        self.srcportrange = None

        self.__pattern = re.compile(r"""^(?P<ip>[.:0-9]*?)(?P<mask>/\d*?)?(?P<dstip>>[.:0-9]*(?P<dstmask>/\d*?)??)?(?P<srcports>%[-0-9]*?)?(?P<dstports>\^[-0-9]*?)?$""")
        match = self.__pattern.match(string)
        if not match:
            raise ValueError("Given string does not match format.")
        mdict = match.groupdict()
        ip = mdict.get("ip", None)
        mask = mdict.get("mask", None)
        if mask and mask != "/32" and mask != "/128":
            ip = ip + mask

        dstip = mdict.get("dstip", None)
        dstmask = mdict.get("dstmask", None)
        if dstip:
            # when ">" was used, we have to distinguish src and dst IP
            self.srcip = ip
            if dstmask == "/32" or dstmask == "/128":
                dstip = dstip[:dstip.find("/")]
            if dstip != ">":
                self.dstip = dstip[1:]
        else:
            self.ip = ip

        srcports = mdict.get("srcports", None)
        dstports = mdict.get("dstports", None)
        if srcports and srcports != '%':
            #skip the leading delimiter and look for range
            r = self.__parse_ports(srcports[1:])
            if isinstance(r, tuple):
                self.srcportrange = r
            else:
                self.srcport = r

        if dstports and dstports != '^':
            #skip the leading delimiter and look for range
            r = self.__parse_ports(dstports[1:])
            if isinstance(r, tuple):
                self.dstportrange = r
            else:
                self.dstport = r
        if self.ip:
            if "/" in self.ip:
                self.ip = pytrap.UnirecIPAddrRange(self.ip)
            else:
                self.ip = pytrap.UnirecIPAddr(self.ip)
        if self.srcip:
            if "/" in self.srcip:
                self.srcip = pytrap.UnirecIPAddrRange(self.srcip)
            else:
                self.srcip = pytrap.UnirecIPAddr(self.srcip)
        if self.dstip:
            if "/" in self.dstip:
                self.dstip = pytrap.UnirecIPAddrRange(self.dstip)
            else:
                self.dstip = pytrap.UnirecIPAddr(self.dstip)

    def __str__(self):
        s = ""
        if self.ip:
            s += str(self.ip)
        else:
            s += (str(self.srcip) if self.srcip else " ") + " -> " + (str(self.dstip) if self.dstip else " ")

        if self.srcportrange:
            s += " : " + str(self.srcportrange[0]) + "-" + str(self.srcportrange[1])
        elif self.srcport:
            s += " : " + str(self.srcport)
        if self.dstportrange:
            s += " -> " + str(self.dstportrange[0]) + "-" + str(self.dstportrange[1])
        elif self.dstport:
            s += " -> " + str(self.dstport)

        return s

    def asTuple(self):
        ip = None
        sip = None
        dip = None
        if self.ip:
            if isinstance(self.ip, pytrap.UnirecIPAddr):
                ip = self.ip
            else:
                ip = (self.ip.start, self.ip.end)
        if self.srcip:
            if isinstance(self.srcip, pytrap.UnirecIPAddr):
                sip = self.srcip
            else:
                sip = (self.srcip.start, self.srcip.end)
        if self.dstip:
            if isinstance(self.dstip, pytrap.UnirecIPAddr):
                dip = self.dstip
            else:
                dip = (self.dstip.start, self.dstip.end)

        return (ip, sip, dip, self.dstport, self.dstportrange, self.srcport, self.srcportrange)

    def __repr__(self):
        return str(self.asTuple())

    def __hash__(self):
        return hash(self.asTuple())
    def __eq__(self, other):
        return self.asTuple() == other.asTuple()
    def __ne__(self, other):
        return not(self == other)

    def __compare_address(self, recaddr, filteraddr):
        if recaddr in filteraddr:
            return True
        else:
            return False

    def __contains__(self, rec):
        if not isinstance(rec, pytrap.UnirecTemplate):
            raise TypeError("Expected UnirecTempate type.")
        sip = rec.SRC_IP
        dip = rec.DST_IP
        sp = rec.SRC_PORT
        dp = rec.DST_PORT

        result = False

        if self.ip:
            if sip in self.ip or dip in self.ip:
                result = True
            else:
                return False
        if self.srcip:
            if sip in self.srcip:
                result = True
            else:
                return False
        if self.dstip:
            if dip in self.dstip:
                result = True
            else:
                return False
        if self.srcport:
            if sp == self.srcport:
                result = True
            else:
                return False
        if self.dstport:
            if dp == self.dstport:
                result = True
            else:
                return False
        if self.dstportrange:
            if dp >= self.dstportrange[0] and dp <= self.dstportrange[1]:
                result = True
            else:
                return False
        if self.srcportrange:
            if sp >= self.srcportrange[0] and sp <= self.srcportrange[1]:
                result = True
            else:
                return False
        return result

class IPBlacklist(Blacklist):
    def __rangesearch(self, a, i, lo, hi):
        """Look for UnirecIPAddr(i) in the sorted list a of UnirecIPAddrRange, use lo and hi indexes.
        This method returns None when i is not found or UnirecIPAddrRange which contains i."""
        while True:
            size = hi - lo
            if size <= 1:
                if i in a[lo]:
                    return a[lo]
                elif hi != lo and i in a[hi]:
                    return a[hi]
                else:
                    return None
            mid = (lo + hi) / 2
            if i in a[mid]:
                return a[mid]
            elif i < a[mid].start:
                hi = mid
            elif i > a[mid].end:
                lo = mid

    def __init__(self, config):
        super(type(self), self).__init__(config)
        lines = []
        self.entities = set()
        self.ips = dict()
        self.srcips = dict()
        self.dstips = dict()
        self.ipsranges = dict()
        self.srcipsranges = dict()
        self.dstipsranges = dict()

        # Load and parse blacklist
        with open(self.path, "r") as f:
            lines = f.readlines()
        for line in lines:
            line = line.strip()
            if line:
                self.entities.add(IPEntity(line))

        # Put addresses of the loaded entities from blacklist into dicts and
        # sorted lists for faster searching.
        for e in self.entities:
            if e.ip:
                if isinstance(e.ip, pytrap.UnirecIPAddr):
                    if e.ip in self.ips:
                        self.ips[e.ip].add(e)
                    else:
                        self.ips[e.ip] = set([e])
                else:
                    if e.ip in self.ipsranges:
                        self.ipsranges[e.ip].add(e)
                    else:
                        self.ipsranges[e.ip] = set([e])
            if e.srcip:
                if isinstance(e.srcip, pytrap.UnirecIPAddr):
                    if e.srcip in self.srcips:
                        self.srcips[e.srcip].add(e)
                    else:
                        self.srcips[e.srcip] = set([e])
                else:
                    if e.srcip in self.srcipsranges:
                        self.srcipsranges[e.srcip].add(e)
                    else:
                        self.srcipsranges[e.srcip] = set([e])
            if e.dstip:
                if isinstance(e.dstip, pytrap.UnirecIPAddr):
                    if e.dstip in self.dstips:
                        self.dstips[e.dstip].add(e)
                    else:
                        self.dstips[e.dstip] = set([e])
                else:
                    if e.dstip in self.dstipsranges:
                        self.dstipsranges[e.dstip].add(e)
                    else:
                        self.dstipsranges[e.dstip] = set([e])
            self.ipsrangeslist = self.ipsranges.keys()
            self.ipsrangeslist.sort()
            self.srcipsrangeslist = self.srcipsranges.keys()
            self.srcipsrangeslist.sort()
            self.dstipsrangeslist = self.dstipsranges.keys()
            self.dstipsrangeslist.sort()

    def __contains__(self, rec):
        """Check if any entity from this blacklist matches rec (UniRec record).

        This function returns True if rec matches the blacklist."""
        if rec.SRC_IP in self.ips:
            entitylist = self.ips[rec.SRC_IP]
            for e in entitylist:
                if rec in e:
                    return True

        if rec.SRC_IP in self.srcips:
            entitylist = self.srcips[rec.SRC_IP]
            for e in entitylist:
                if rec in e:
                    return True

        if rec.DST_IP in self.ips:
            entitylist = self.ips[rec.DST_IP]
            for e in entitylist:
                if rec in e:
                    return True

        if rec.DST_IP in self.dstips:
            entitylist = self.dstips[rec.DST_IP]
            for e in entitylist:
                if rec in e:
                    return True

        if self.ipsrangeslist:
            hi = len(self.ipsrangeslist) - 1
            key = self.__rangesearch(self.ipsrangeslist, rec.DST_IP, 0, hi)
            if key:
                for e in self.ipsranges[key]:
                    if rec in e:
                        return True
            key = self.__rangesearch(self.ipsrangeslist, rec.SRC_IP, 0, hi)
            if key:
                for e in self.ipsranges[key]:
                    if rec in e:
                        return True

        if self.srcipsrangeslist:
            hi = len(self.srcipsrangeslist) - 1
            key = self.__rangesearch(self.srcipsrangeslist, rec.SRC_IP, 0, hi)
            if key:
                for e in self.srcipsranges[key]:
                    if rec in e:
                        return True
        if self.dstipsrangeslist:
            hi = len(self.dstipsrangeslist) - 1
            key = self.__rangesearch(self.dstipsrangeslist, rec.DST_IP, 0, hi)
            if key:
                for e in self.dstipsranges[key]:
                    if rec in e:
                        return True
        return False

    def __str__(self):
        s = super(type(self), self).__str__() + " containing:\n"
        for entity in self.entities:
            s += "* " + str(entity) + "\n"
        return s

def load_config(config_file):
    blacklists = {}
    config = {}
    with open(config_file, "r") as f:
        config = yaml.load(f)
    for blname in config:
        c = config[blname]
        filter_type =  c.get("filter_type", None)
        if not filter_type:
            raise KeyError("Mandatory key `filter_type` was not found for " + blname + " blacklist.")
        if filter_type == "ip":
            blacklists[blname] = IPBlacklist(c)
    return blacklists

#=======================
# { Start of Testing code
#=======================

testno = 1

def assertTrue(t, b):
    global testno
    print(str(testno) + " expected True")
    print(t.strRecord())
    if t in b:
        print("success")
    else:
        print("error")
        print("")
    testno += 1

def assertFalse(t, b):
    global testno
    print(str(testno) + " expected False")
    print(t.strRecord())
    if not (t in b):
        print("success")
    else:
        print("error")
        print("")
    testno += 1

def test():
    try:
        bs = load_config("config-malf.yml")
        raise Exception("accepted invalid configuration")
    except Exception as e:
        #print(e)
        pass

    print("Config:")
    bs = load_config("testconfig.yml")
    for b in bs:
        print(str(bs[b]))

    print("Tests:")
    tmplt = pytrap.UnirecTemplate("ipaddr SRC_IP,ipaddr DST_IP,uint16 SRC_PORT,uint16 DST_PORT")
    tmplt.createMessage()
    tmplt.DST_IP = pytrap.UnirecIPAddr("0.0.0.0")
    tmplt.SRC_IP = pytrap.UnirecIPAddr("1.2.3.4")
    assertTrue(tmplt, bs[b])

    tmplt.SRC_IP = pytrap.UnirecIPAddr("1.2.4.1")
    assertTrue(tmplt, bs[b])

    tmplt.SRC_IP = pytrap.UnirecIPAddr("10.0.0.1")
    assertFalse(tmplt, bs[b])

    tmplt.DST_IP = pytrap.UnirecIPAddr("10.0.1.1")
    assertFalse(tmplt, bs[b])

    tmplt.DST_PORT = 1025
    assertFalse(tmplt, bs[b])

    tmplt.DST_PORT = 1024
    assertTrue(tmplt, bs[b])

    tmplt.SRC_PORT = 1024
    assertTrue(tmplt, bs[b])

    tmplt.DST_IP = pytrap.UnirecIPAddr("10.2.1.1")
    assertTrue(tmplt, bs[b])

    # 1.2.3.4
    # 1.2.4.0/30
    # 10.0.0.0/20>10.0.1.0/24%^1-1024
    # 10.1.0.0/20>%1-1024^
    # >10.2.0.0/20%1-1024^
    # >1.1.1.1%^80
    # >1.1.1.2%8080^80
    # >2.2.2.3/32
    # >2.2.2.4/32%^
    # 2.2.2.5/32>%^
    # 2.2.2.6/32

    import sys
    sys.exit()

#=======================
# } End of Testing code
#=======================



def main():
    blacklists = load_config("config.yml")
    trap = pytrap.TrapCtx()
    trap.init(sys.argv, 1, 1)

    # Set the list of required fields in received messages.
    # This list is an output of e.g. flow_meter - basic flow.
    inputspec = "ipaddr DST_IP,ipaddr SRC_IP,uint16 SRC_PORT,uint16 DST_PORT"
    fmttype = pytrap.FMT_UNIREC
    trap.setRequiredFmt(0, fmttype, inputspec)
    trap.setDataFmt(0, fmttype, inputspec)
    rec = pytrap.UnirecTemplate(inputspec)

    # Main loop
    i=1
    while True:
        try:
            data = trap.recv()
        except pytrap.FormatChanged as e:
            fmttype, inputspec = trap.getDataFmt(0)
            rec = pytrap.UnirecTemplate(inputspec)
            trap.setDataFmt(0, fmttype, inputspec)
            data = e.data
        if len(data) <= 1:
            break
        rec.setData(data)

        i += 1
        if i==1000000:
            break
        for bl in blacklists:
            if rec in blacklists[bl]:
                #print("{0} in {1}.".format(rec.strRecord(), bl))
                trap.send(rec.getData(), 0)

    # Free allocated TRAP IFCs
    trap.finalize()
    print("Processed: {0} flows".format(i))


if __name__ == "__main__":
    if "--test" in sys.argv:
        test()
    else:
        main()

