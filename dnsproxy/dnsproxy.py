#!/usr/bin/env python

'''
DNS Proxy server
Config file in dnsproxy.conf

Requires python-daemon
Requires plogger
'''

#Option parser
from optparse import OptionParser

#Socket server
import SocketServer

#lock
import lockfile

#Signals
#import signal

#Daemon class
import daemon

#Config
import ConfigParser
import ast

from dnsdata import Dns_Packet

#Logging
import logging
from plogger.plogger import plogger

#Global Config
CONFIG = config=ConfigParser.RawConfigParser()

#Global Logging
loglevel = 'DEBUG'
level=logging.getLevelName(loglevel)
logger = plogger(level, 'dnsproxy')

def HandleQueries(querydata, addr, server):
    ''' Handle DNS Queries '''

    if len(querydata) < 12:
        return

    mydata = Dns_Packet(querydata, logger)
    a_domain = mydata.domain()

    nameserver = '127.0.0.1:53'
    fallback_nameserver = '127.0.0.1:53'
    Mask = None
    domain_routing = False
    rewrite = ast.literal_eval(config.get('dnsproxy', 'rewrite')) if config.has_option('dnsproxy', 'rewrite') else []
    nameserver = config.get('dnsproxy', 'nameserver') if config.has_option('dnsproxy', 'nameserver') else None
    fallback_nameserver = config.get('dnsproxy', 'fallback_nameserver') if config.has_option('dnsproxy', 'fallback_nameserver') else None
    A = config.get('dnsproxy', 'A') if config.has_option('dnsproxy', 'A') else None
    TXT = config.get('dnsproxy', 'TXT') if config.has_option('dnsproxy', 'TXT') else None
    MX = config.get('dnsproxy', 'MX') if config.has_option('dnsproxy', 'MX') else None
    SOA = config.get('dnsproxy', 'SOA') if config.has_option('dnsproxy', 'SOA') else None
    PTR = config.get('dnsproxy', 'PTR') if config.has_option('dnsproxy', 'PTR') else None
    CNAME = config.get('dnsproxy', 'CNAME') if config.has_option('dnsproxy', 'CNAME') else None
    Domains = ast.literal_eval(config.get('dnsproxy', 'Domains')) if config.has_option('dnsproxy', 'Domains') else None

    response = None

    # Rewritting:
    for item in rewrite:
        src_list = item.split(':')[0].split('.')
        dom_list = mydata.domain().split('.')[-len(src_list):]
        if src_list == dom_list:
        #if item.split(':')[0] in mydata.domain():
            new_query = mydata.domain().replace(item.split(':')[0],item.split(':')[1])
            logger.info('Rewritting query {} to {}'.format(mydata.domain(), new_query))
            mydata.rewrite(new_query)
            Mask = new_query

    QUERY = mydata.querytypestring()

    # Domain based Routing
    if Domains:
        for dom in Domains:
            src = dom.split('=')[0]
            src_list = src.split('.')
            dst = dom.split('=')[1].split(':')[0]
            dst_port = int(dom.split('=')[1].split(':')[1])
            dom_list = mydata.domain().split('.')[-len(src_list):]
            if dom_list == src_list:
            #if src in mydata.domain():
                logger.info("Redirecting {} queries To {}".format(src,dst))
                response = mydata.QueryDNS(dst, dst_port)
                domain_routing = True
                break
    # Question based routing
    if domain_routing == False:
        try:
            querytype = locals()[QUERY]
            if querytype:
                logger.info("Redirecting {} Request to {} for {}".format(QUERY, querytype, mydata.domain()))
                response = mydata.QueryDNS(querytype.split(':')[0],int(querytype.split(':')[1]))
            else:
                logger.info("Using default dns for {}".format(mydata.domain()))
                response = mydata.QueryDNS(nameserver.split(':')[0],int(nameserver.split(':')[1]))

        except:
            logger.error("Error Contacting Name server")

    if not response is None:
    #if not response is None or check_dns_packet(response, mydata.querytype()):
        myanswer = Dns_Packet(response[2:], logger)
        if Mask: myanswer.forge_dns_packet(a_domain)
        logger.debug("Answer OK for {} sending back to client".format(mydata.domain()))
        sendbuf = myanswer.getdata()
        server.sendto(sendbuf, addr)

    #Fall back to backup dns server list
    else:
        try:
            logger.info("Nameserver not available, falling back to {}".format(fallback_nameserver))
            response = mydata.QueryDNS(fallback_nameserver.split(':')[0],int(fallback_nameserver.split(':')[1]))
        except:
            logger.info("Nameserver {} is not available".format(fallback_nameserver))

        if not response is None:
        #if not response is None or check_dns_packet(response, mydata.querytype()):
            myanswer = Dns_Packet(response[2:], logger)
            if Mask: myanswer.forge_dns_packet(a_domain)
            logger.debug("Answer OK on fallback server {}, for {} sending back to client".format(fallback_nameserver,mydata.domain()))
            sendbuf = myanswer.getdata()
            server.sendto(sendbuf, addr)

class ThreadedUDPRequestHandler(SocketServer.BaseRequestHandler):
    ''' Request Handler '''

    global logger

    daemon_threads = True
    allow_reuse_address = True

    def handle(self):
        data = self.request[0]
        socket = self.request[1]
        addr = self.client_address
        logger.warning('Connect from {} port {}'.format(addr[0],addr[1]))
        HandleQueries(data, addr, socket)

class ThreadedUDPServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):
    ''' Start UDP Server '''
    def __init__(self, s, t):
        logger.info('Ready to handle queries!')
        SocketServer.UDPServer.__init__(self, s, t)

def thread_main(host, port):
    ''' main '''

    global CONFIG, logger, loglevel, logfile
    loglevel = 'INFO'
    if config.has_option('logger', 'loglevel'): loglevel = config.get('logger', 'loglevel')
    level = logging.getLevelName(loglevel)
    logfile = 'dnsproxy.log'
    if config.has_option('logger','logfile'): logfile = config.get('logger','logfile')
    logger.fileHandler(logfile,level)

    server = ThreadedUDPServer((host, port), ThreadedUDPRequestHandler)
    server.serve_forever()
    server.shutdown()

def main():
    ''' start the code '''
    global CONFIG, loglevel, level, logger

    #Option parser
    usage="usage: %prog \n    configuration paramaters should be in dnsproxy.conf"
    parser=OptionParser(usage)
    parser.add_option("-f","--foreground",action="store_true",help="Does not start as a Daemon")
    parser.add_option("-c","--configfile",dest="configfile",help="Load corresponding configuration file")

    (options, args)=parser.parse_args()


    conf = 'dnsproxy.conf'
    if options.configfile:
        conf = options.configfile

    try:
        CONFIG.readfp(open(conf))
    except:
        print "Could not open configuration file \"{}\"".format(conf)
        exit(1)

    host = '127.0.0.1'
    port  = 53
    if config.has_option('dnsproxy','host'): host = CONFIG.get('dnsproxy','host')
    if config.has_option('dnsproxy','port'): port = int(CONFIG.get('dnsproxy','port'))

    pid = './dnsproxy.pid'
    if config.has_option('dnsproxy','pidfile'): pid = CONFIG.get('dnsproxy','pidfile')

    work = '/var/tmp'
    if config.has_option('dnsproxy','workdir'): work = CONFIG.get('dnsproxy','workdir')

    context = daemon.DaemonContext(
        working_directory=work,
        umask=0o002,
        pidfile=lockfile.FileLock(pid),
        )

    #Start daemon
    if options.foreground:
        thread_main(host,port)
    else:
        with context: thread_main(host,port)

if __name__ == "__main__":
    main()
