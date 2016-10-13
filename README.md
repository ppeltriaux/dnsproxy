# dnsProxy

dns proxy service able to reroute dns request upon type of queries, domain and also able to rewrite (masquerade) queries

## Installation

This tool requires **plogger** and **python-daemon**

#### Install
```
pip install git+https://gitlab.service-now.com/pascal.peltriaux/dnsproxy.git --process-dependency-links --allow-all-external
```

## Setup

Get and edit dnsproxy.conf sample file from git

```
wget https://gitlab.service-now.com/pascal.peltriaux/dnsproxy/raw/master/etc/dnsproxy.conf --no-check-certificate
```

#### Edit dnsproxy.conf

```
#Host to bind to
[dnsproxy]
host: 127.0.0.1
```

```
#Port to listen on
port: 2053
```

```
#Pid file location and workdir (This directory has to be rw by the user starting the proxy)
pidfile: /var/tmp/dnsproxy.pid
workdir: /var/tmp
```
```
#Default nameserver to query
nameserver: 10.249.5.11:53
```

```
#Fallback nameserver to query
fallback_nameserver: 10.249.5.11:53
```

```
#Txt record nameserver to redirect to
TXT: 127.0.0.1:53
```

```
#A record nameserver to redirect to
A: 127.0.0.1:53
```

```
#SOA record nameserver to redirect to
SOA: 127.0.0.1:53
```

```
#MX record nameserver to redirect to
MX: 127.0.0.1:53
```

```
#CNAME record nameserver to redirect to
CNAME: 127.0.0.1:53
```

```
#PTR record nameserver to redirect to
PTR: 127.0.0.1:53
```

```
#Domain masquerading list will send query for listed domain to corresponding NS
Domains: [   'google.com=127.0.0.1:53',
             'test.com=127.0.0.1:53']
```

```
#Domain rewrite (Will rewrite one domain by another in the query)
rewrite=[   'pascal.com:service-now.com',
            's.com:service-now.com',
            'google.com:servicenow.com']
```

```
[logger]
logfile=/var/tmp/dnsproxy.log
loglevel=DEBUG
```

## Usage

```
Usage: dnsproxy.py
    configuration paramaters should be in dnsproxy.conf

Options:
  -h, --help            show this help message and exit
  -f, --foreground      Does not start as a Daemon
  -c CONFIGFILE, --configfile=CONFIGFILE
                        Load corresponding configuration file
```
