#!/usr/bin/env python

'''
DNS Proxy server
Config file in dnsproxy.conf
'''

import struct
import socket

query_type = {'\x00\x05' : 'CNAME',
'\x00\x10' : 'TXT',
'\x00\x01' : 'A',
'\x00\x0f' : 'MX',
'\x00\x06' : 'SOA',
'\x00\x0c' : 'PTR'}

class Dns_Packet():

    def __init__(self, data, logger = None):
        ''' initialise valies '''
        self.data = data
        self.logger = logger

        #print map(lambda c: hex(ord(c)), self.data)
        self.TID = data[0:2]
        self.Flags = data[2:4]
        self.Questions = data[4:6]
        self.AnswerRRs = data[6:8]
        self.AuthorityRRs = data[8:10]
        self.AdditionalRRs = data[10:12]
        self.q_domain, lengh = self.__bytetodomain(data[12:])
        #print self.q_domain
        self.SEARCHTYPE = self.data[12+lengh:12+lengh+2]
        self.SEARCHCLASS = self.data[12+lengh+2:12+lengh+4]
        self.REWRITE = None

    def domain(self,domain=None):
        ''' return the domain queried '''
        if domain: self.q_domain = domain
        return self.q_domain

    def querytype(self):
        ''' return the type of query '''
        return self.SEARCHTYPE

    def querytypestring(self):
        ''' return the type of query '''
        return query_type[self.SEARCHTYPE]

    def rewrite(self, domain):
        ''' set rewrite flag and value '''
        self.REWRITE = domain

    def getdata(self):
        ''' return the value of the data '''
        return self.data

    def gettid(self):
        ''' return the value of the data '''
        return self.TID

    def __printdata(self,data):
        ''' debug function to print data '''
        print map(lambda c: hex(ord(c)), data)

    def __rewritepointer(self, pointer, DIFF, offset):
        ''' Modify pointer to correct value in data '''
        POINTER = 49152
        pointer_val = int(struct.unpack('!H', pointer)[0]) - POINTER
        if pointer_val > offset: pointer_val = pointer_val - DIFF
        pointer_val += POINTER
        pointer = struct.pack('!H', pointer_val)
        return pointer

    def forge_dns_packet(self, dest=None):
        ''' Rewrite the domain queried by the one specified '''

        '''head section'''
        #head = self.data[0:8] + '\x00\x00\x00\x00'
        head = self.data[0:12]
        source, slengh = self.__bytetodomain(self.data[12:])
        if dest == None: dest = source
        bsource = self.__domaintobyte(source)
        bdest = self.__domaintobyte(dest)
        DIFF = slengh - len(bdest)
        offset = len(head+bsource)
        answer = head + bdest + self.SEARCHTYPE + self.SEARCHCLASS

        ''' answer + ns + adds section '''
        pos = len(head)+slengh+4
        answers = int(struct.unpack('!h', self.AnswerRRs)[0])
        authority = int(struct.unpack('!h', self.AuthorityRRs)[0])
        adds = int(struct.unpack('!h', self.AdditionalRRs)[0])
        i = answers + authority + adds

        while i != 0 :
            #print i
            #self.__printdata(self.data[pos:])
            pointer = self.data[pos:pos+2]
            block_type = self.data[pos+2:pos+4]
            block_class = self.data[pos+4:pos+6]
            block_ttl = self.data[pos+6:pos+10]
            block_data_lengh = self.data[pos+10:pos+12]
            pointer = self.__rewritepointer(pointer, DIFF, offset)
            answer += pointer + block_type + block_class + block_ttl + block_data_lengh
            pos += 12

            if pointer == '\x00\x00':
                answer += self.data[pos:]
                i -= 1
                break
            bsize = int(struct.unpack('!h', block_data_lengh)[0])
            btype = int(struct.unpack('!h', block_type)[0])
            #Rewrite data block with pointer
            if btype == 2 or btype == 5 or btype == 6:
                #print 'NS SERVER {}'.format(btype)
                while bsize > 0:
                    val = int(struct.unpack('!B', self.data[pos:pos+1])[0])
                    #print val
                    if val < 192:
                        #print "sub value"
                        #self.__printdata(self.data[pos:pos+val+1])
                        answer += self.data[pos:pos+val+1]
                        pos += val+1
                        bsize -= val+1
                    else:
                        #print "sub pointer"
                        #self.__printdata(self.data[pos:pos+2])
                        pointer = self.__rewritepointer(self.data[pos:pos+2], DIFF, offset)
                        answer += pointer
                        pos += 2
                        bsize -= 2
            else:
                #print 'DIRECT'
                answer += self.data[pos:pos+bsize]
                pos += bsize
            i -= 1
        #print map(lambda c: hex(ord(c)), self.data[pos:])
        self.data = answer
        self.q_domain = dest

    def QueryDNS(self, server, port):
        ''' Send Data to a DNS Server '''

        data = self.__buildquery()
        Buflen = struct.pack('!h', len(data))
        sendbuf = Buflen + data

        data = None
        try:
            protocol = socket.SOCK_STREAM
            s = socket.socket(socket.AF_INET, protocol)

            # set socket timeout
            timeout = 10
            s.settimeout(timeout)
            s.connect((server, int(port)))
            s.send(sendbuf)
            data = s.recv(2048)
        except Exception as e:
            self.logger.error('Server %s: %s' % (server, str(e)))
        finally:
            if s:
                s.close()
            return data

    def __buildquery(self):
        ''' Build Query to send to DNS '''
        domain = self.q_domain
        if self.REWRITE : domain = self.REWRITE
        self.forge_dns_packet(domain)
        Buf = self.getdata()

        return Buf

    def __bytetodomain(self, s):
        ''' Convert bytes to domain name '''
        domain = ''
        i = 0
        length = struct.unpack('!B', s[0:1])[0]

        while length != 0:
            i += 1
            domain += s[i:i + length]
            i += length
            length = struct.unpack('!B', s[i:i + 1])[0]
            if length != 0:
                domain += '.'

        return domain, i+1

    def __domaintobyte(self, domain):
        ''' Convert a domain name to bytes '''
        domaintobyte = ''
        dsplit = domain.split('.')
        for cs in dsplit:
            formatstr = 'B%ds' % len(cs)
            newsplit = struct.pack(formatstr,len(cs),cs)
            domaintobyte += newsplit
        domaintobyte += '\0'
        return domaintobyte
