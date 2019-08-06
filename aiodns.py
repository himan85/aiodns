#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright: 2014-2015 clowwindy, 2019 john
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import asyncio
import socket
import struct
import os
import ipaddress
import re
import collections
import time

# rfc1035
# format
# +---------------------+
# |        Header       |
# +---------------------+
# |       Question      | the question for the name server
# +---------------------+
# |        Answer       | RRs answering the question
# +---------------------+
# |      Authority      | RRs pointing toward an authority
# +---------------------+
# |      Additional     | RRs holding additional information
# +---------------------+
#
# header
#                                 1  1  1  1  1  1
#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      ID                       |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    QDCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ANCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    NSCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ARCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

QTYPE_ANY = 255
QTYPE_A = 1
QTYPE_AAAA = 28
QTYPE_CNAME = 5
QTYPE_NS = 2
QCLASS_IN = 1
TYPES = collections.namedtuple('Types', ['A', 'CNAME', 'AAAA'])(A=1, CNAME=5, AAAA=28)
VALID_HOSTNAME = re.compile(br"(?!-)[A-Z\d\-_]{1,63}(?<!-)$", re.IGNORECASE)


def is_valid_hostname(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == b'.':
        hostname = hostname[:-1]
    return all(VALID_HOSTNAME.match(x) for x in hostname.split(b'.'))


def compat_ord(s):
    if type(s) == int:
        return s
    return _ord(s)


def compat_chr(d):
    if bytes == str:
        return _chr(d)
    return bytes([d])


_ord = ord
_chr = chr
ord = compat_ord
chr = compat_chr


def build_address(address):
    address = address.strip(b'.')
    labels = address.split(b'.')
    results = []
    for label in labels:
        l = len(label)
        if l > 63:
            return None
        results.append(chr(l))
        results.append(label)
    results.append(b'\0')
    return b''.join(results)


def build_request(address, qtype):
    request_id = os.urandom(2)
    header = struct.pack('!BBHHHH', 1, 0, 1, 0, 0, 0)
    addr = build_address(address)
    qtype_qclass = struct.pack('!HH', qtype, QCLASS_IN)
    return request_id + header + addr + qtype_qclass


class DnsResolver():
    
    def __init__(self, loop, name_server, ttl = 86400, lru_max = 200):
        self._QTYPES = [QTYPE_A, QTYPE_AAAA]
        self._hosts = {}
        self._parse_hosts()
        self._name_server = name_server
        self._loop = loop
        self._ttl = ttl
        self._cache = LruCache(lru_max)

    async def resolve(self, hostname,qtype):
        if type(hostname) != bytes:
            hostname = hostname.encode('utf8')
        response = DNSResponse()
        response.hostname = hostname
        if not hostname:
            raise Exception('empty hostname!')
        if is_ip(hostname):
            # print('hostname is ip: {}'.format(hostname))
            response.answers.append((hostname.decode('utf8'),0,0))
            response.status = 'is_ip'
            return response
        if hostname in self._hosts:
            # print('hit hosts: {}'.format(hostname))
            ip = self._hosts[hostname]
            response.answers.append((ip.decode('utf8'),0,0))
            response.status = 'hit_hosts'
            return response
        now = round(time.time())
        cache_result = self._cache.get(hostname)
        if cache_result: 
            if now - cache_result[1] < self._ttl:
                # print('hit cache: {}'.format(cache_result))
                response.answers = cache_result[0]
                response.status = 'hit_cache'
                return response
            else:
                return await self._send_req(response, hostname, qtype)
        else:
            # print('not in cache: {}'.format(hostname))
            return await self._send_req(response, hostname, qtype)
    
    async def _send_req(self, response, hostname, qtype):
        if not is_valid_hostname(hostname):
            raise Exception('invalid hostname:{}'.format(hostname))
        req = build_request(hostname, self._QTYPES[0])
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.connect(self._name_server)
        await self._loop.sock_sendall(sock, req)
        try:
            rsp = await asyncio.wait_for(self._loop.sock_recv(sock,512), 5)
        except asyncio.TimeoutError:
            self._close_sock(self._loop, sock)
            raise Exception('wait for dns response timeout!')
        sock.close()
        re_time = round(time.time())
        response = parse_response(response, rsp, qtype)
        self._cache.put(hostname,(response.answers,re_time))
        return response

    def _parse_hosts(self):
        etc_path = '/etc/hosts'
        if 'WINDIR' in os.environ:
            etc_path = os.environ['WINDIR'] + '/system32/drivers/etc/hosts'
        try:
            with open(etc_path, 'rb') as f:
                for line in f.readlines():
                    line = line.strip()
                    parts = line.split()
                    
                    if len(parts) < 2:
                        continue

                    ip = parts[0]
                    
                    if not is_ip(ip):
                        continue
                    
                    for i in range(1, len(parts)):
                        hostname = parts[i]
                        if hostname:
                            self._hosts[hostname] = ip
        except IOError:
            self._hosts['localhost'] = '127.0.0.1'

    def _close_sock(self, loop, sock):
        try:
            loop.remove_reader(sock.fileno())
        except NotImplementedError:
            pass
        finally:
            sock.close()


def is_ip(ipaddr):
    if type(ipaddr) != str:
        ipaddr = ipaddr.decode('utf8')
    try:
        ipaddress.ip_address(ipaddr)
        return True
    except :
        return False

 
def parse_ip(addrtype, data, length, offset):
    if addrtype == QTYPE_A:
        return socket.inet_ntop(socket.AF_INET, data[offset:offset + length])
    elif addrtype == QTYPE_AAAA:
        return socket.inet_ntop(socket.AF_INET6, data[offset:offset + length])
    elif addrtype in [QTYPE_CNAME,QTYPE_NS]:
        return parse_name(data, offset)[1]
    else:
        return data[offset:offset + length]


def parse_name(data, offset):
    p = offset
    labels = []
    l = data[p]
    while l > 0:
        if (l & (128 + 64)) == (128 + 64):
            # pointer
            pointer = struct.unpack('!H', data[p:p + 2])[0]
            pointer &= 0x3FFF
            r = parse_name(data, pointer)
            labels.append(r[1])
            p += 2
            # pointer is the end
            return p - offset, b'.'.join(labels)
        else:
            labels.append(data[p + 1:p + 1 + l])
            p += 1 + l
        l = data[p]

    return p - offset + 1, b'.'.join(labels)


def parse_header(data):
    if len(data) >= 12:
        header = struct.unpack('!HBBHHHH', data[:12])
        res_id = header[0]
        res_qr = header[1] & 128
        res_tc = header[1] & 2
        res_ra = header[2] & 128
        res_rcode = header[2] & 15
        # assert res_tc == 0
        # assert res_rcode in [0, 3]
        res_qdcount = header[3]
        res_ancount = header[4]
        res_nscount = header[5]
        res_arcount = header[6]
        return (res_id, res_qr, res_tc, res_ra, res_rcode, res_qdcount,
                res_ancount, res_nscount, res_arcount)
    return None


def parse_response(response, data, qtype):
    try:
        if len(data) >= 12:
            header = parse_header(data)
            if not header:
                return None
            res_id, res_qr, res_tc, res_ra, res_rcode,\
                res_qdcount, res_ancount, res_nscount, res_arcount = header

            qds = []
            ans = []
            offset = 12
            for i in range(0, res_qdcount):
                l, r = parse_record(data, offset, True)
                offset += l
                if r:
                    qds.append(r)
            for i in range(0, res_ancount):
                l, r = parse_record(data, offset)
                offset += l
                if r:
                    ans.append(r)
            for i in range(0, res_nscount):
                l, r = parse_record(data, offset)
                offset += l
            for i in range(0, res_arcount):
                l, r = parse_record(data, offset)
                offset += l
            if qds:
                response.hostname = qds[0][0]
            for an in qds:
                response.questions.append((an[1], an[2], an[3]))
            for an in ans:
                if an[2] == qtype:
                    response.answers.append((an[1], an[2], an[3]))
            response.status = 'resolve'
            return response
    except Exception:
        return None


# rfc1035
# record
#                                    1  1  1  1  1  1
#      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                                               |
#    /                                               /
#    /                      NAME                     /
#    |                                               |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                      TYPE                     |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                     CLASS                     |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                      TTL                      |
#    |                                               |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                   RDLENGTH                    |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
#    /                     RDATA                     /
#    /                                               /
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

def parse_record(data, offset, question=False):
    nlen, name = parse_name(data, offset)
    if not question:
        record_type, record_class, record_ttl, record_rdlength = struct.unpack(
            '!HHiH', data[offset + nlen:offset + nlen + 10]
        )
        ip = parse_ip(record_type, data, record_rdlength, offset + nlen + 10)
        return nlen + 10 + record_rdlength, \
            (name, ip, record_type, record_class, record_ttl)
    else:
        record_type, record_class = struct.unpack(
            '!HH', data[offset + nlen:offset + nlen + 4]
        )
        return nlen + 4, (name, None, record_type, record_class, None, None)


class DNSResponse():
    def __init__(self):
        self.hostname = None
        self.status = None
        self.questions = []  # each: (addr, type, class)
        self.answers = []  # each: (addr, type, class)

    def __str__(self):
        return '%s: %s' % (self.hostname, str(self.answers))


class LruCache():

    def __init__(self, capacity):
        self._capacity = capacity
        self._queue = collections.OrderedDict()

    def get(self, key):
        if key not in self._queue:
            return None 
        value = self._queue.pop(key) 
        self._queue[key] = value 
        return self._queue[key]

    def put(self, key, value):
        if key in self._queue:
            self._queue.pop(key)
        elif len(self._queue.items()) == self._capacity:
            self._queue.popitem(last=False)
        self._queue[key] = value

    def pop(self, key):
        if key in self._queue:
            self._queue.pop(key)


def elapsed(stime):
    el = time.time() - stime
    return int(round(el * 1000))


async def test0(hostname,qtype,loop):
    try:
        stime = time.time()
        response = await dns_resolver.resolve(hostname,qtype)
        # print(response)
        print('{}: {}, {}, time elapsed: {}ms'.format(hostname, response.answers, response.status, elapsed(stime)))
    except Exception as e:
        print(e)


async def test1(hostname,qtype,loop):
    try:
        await asyncio.sleep(1)
        stime = time.time()
        response = await dns_resolver.resolve(hostname,qtype)
        # print(response)
        print('{}: {}, {}, time elapsed: {}ms'.format(hostname, response.answers, response.status, elapsed(stime)))
    except Exception as e:
        print(e)


async def test2(hostname,qtype,loop):
    try:
        await asyncio.sleep(3)
        stime = time.time()
        response = await dns_resolver.resolve(hostname,qtype)
        # print(response)
        print('{}: {}, {}, time elapsed: {}ms'.format(hostname, response.answers, response.status, elapsed(stime)))
    except Exception as e:
        print(e)
    

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    # loop = asyncio.ProactorEventLoop()
    dns_resolver = DnsResolver(loop, ('8.8.8.8', 53), ttl =2)
    loop.create_task(test0('www.google.com',TYPES.A, loop))
    loop.create_task(test1('www.google.com',TYPES.A, loop))
    loop.create_task(test2('www.google.com',TYPES.A, loop))
    loop.create_task(test0('www.amazon.co.jp',TYPES.A, loop))
    loop.create_task(test0('192.168.1.1',TYPES.A, loop))
    loop.create_task(test0(b'www.google.com',TYPES.A, loop))
    loop.create_task(test0('www.baidu.com',TYPES.A, loop))
    loop.create_task(test0('www.baidu.com',TYPES.CNAME, loop))
    loop.create_task(test0('ipv6.google.com',TYPES.AAAA, loop))
    loop.create_task(test0('ns2.google.com',TYPES.A, loop))
    loop.create_task(test0('example.com',TYPES.A, loop))
    loop.create_task(test0('tooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooolong.hostname',TYPES.A, loop))
    loop.create_task(test0('invalid.@!#$%^&$@.hostname',TYPES.A, loop))
    loop.run_forever()
	