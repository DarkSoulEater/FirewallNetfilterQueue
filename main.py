from netfilterqueue import NetfilterQueue
from scapy.all import *
import argparse
import re
import enum
import sys
from io import StringIO

class Status(enum.Enum):
    accept = 0
    drop = 1
    skip = 2

class Rule():
    def __init__(self, str:str):
        rule_type = str.split()[0]
        assert(rule_type in ['accept', 'drop'])
        if rule_type == 'accept':
            self.accept = True
            self.name = r'.*'
            self.type = r'.*'
            self.data = r'.*'
        elif rule_type == 'drop':
            self.accept = False
            self.name = r'.*'
            self.type = r'.*'
            self.data = r'.*'

        name = re.search(r'name\s*=\s*\'\S+\'', str)
        if name:
            self.name = (re.search(r'\'.+\'', name[0]))[0]
            self.name = self.name[1:-1]
            if self.name[-1] != '.':
                self.name += '.'


        type = re.search(r'type\s*=\s*\'\S+\'', str)
        if type:
            self.type = (re.search(r'\'.+\'', type[0]))[0]
            self.type = self.type[1:-1]

        data = re.search(r'data\s*=\s*\'\S\'', str)
        if data:
            self.data = (re.search(r'\'.+\'', data[0]))[0]

        print("Rule:")
        print('\tName = ', self.name)
        print('\tType = ', self.type)
        print('\tData = ', self.data)
        return
    
    def search(self, dns):
        match = True
        for an in dns.an:
            old_stdout = sys.stdout
            sys.stdout = mystdout = StringIO()
            an.show()
            sys.stdout = old_stdout
            an_str = mystdout.getvalue()

            # print("AN: ", an_str)

            name = re.search(self.name, an.rrname.decode())
            if not name:
                print("NM: Name: ", an.rrname.decode(), self.name)
                match = False

            type = re.search(r'type\s*=\s*' + self.type, an_str)
            if not type:
                print("NM: Type: ", an_str, r'type\s*=\s*' + self.type)
                match = False

            # print(an.rdata)

            data = re.search(self.data, an.rdata)
            if not data:
                print("NM: Data: ", an.rdata, self.data)
                match = False

            # print(type(an.type))
            # print(an.summary())
            # type = re.search(self.name, an.type.decode())

        if match == False:
            return Status.skip
        elif self.accept == True:
            return Status.accept
        else:
            return Status.drop

def parse_file(path):
    rules = []

    with open(path, "r") as inp:
        lines = inp.readlines()

    for line in lines:
        rules.append(Rule(line))

    return rules

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--rules_file', type=str, default='rules.txt', dest='rules_path', help='path to rules file')
    parser.add_argument('-q', '--queue-num', type=int, default=5, dest='queue_num', help='nfqueue number')
    return parser.parse_args()

def main():
    args = get_arguments()

    rules = parse_file(args.rules_path)

    def callback(pkt):
        print(pkt)
        if pkt.hw_protocol != 0x0800: # If not IPv4
            pkt.accept()
            return;

        ip = IP(pkt.get_payload())
        if not ip.haslayer(DNS): # If not DNS
            pkt.accept()
            return;

        dns = ip[DNS]
        print("Recv DNS: ", dns)

        if dns.qr == 0:
            pkt.accept()
            return
        
        # dns.show()

        for rule in rules:
            res = rule.search(dns)
            if res == Status.accept:
                pkt.accept()
                print("ACCEPT")
                return
            elif res == Status.drop:
                pkt.drop()
                print("DPOR")
                return

        pkt.accept()
        return

    nfqueue = NetfilterQueue()
    nfqueue.bind(args.queue_num, callback)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print('')

    nfqueue.unbind()

if __name__ == '__main__':
    main()