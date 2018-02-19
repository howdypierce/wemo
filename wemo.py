#!/usr/bin/python
#
# Control a WeMo device on your local network.
#
# Howdy Pierce, howdy@cardinalpeak.com
#
#

import re
import requests
import sys
import os
import StringIO
import socket
import httplib
from time import sleep

###############################################################################
#   Copyright 2014 Dan Krause
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.


class SSDPResponse(object):
    class _FakeSocket(StringIO.StringIO):
        def makefile(self, *args, **kw):
            return self

    def __init__(self, response):
        r = httplib.HTTPResponse(self._FakeSocket(response))
        r.begin()
        self.location = r.getheader("location")
        self.usn = r.getheader("usn")
        self.st = r.getheader("st")
        self.cache = r.getheader("cache-control").split("=")[1]

    def __repr__(self):
        st = "<SSDPResponse({location}, {st}, {usn})>"
        return st.format(**self.__dict__)


def ssdp_discover(service, interface="0.0.0.0", timeout=2, retries=1):
    group = ("239.255.255.250", 1900)
    message = "\r\n".join([
        'M-SEARCH * HTTP/1.1',
        'HOST: {0}:{1}',
        'MAN: "ssdp:discover"',
        'ST: {st}', 'MX: {mx}', '', ''])
    socket.setdefaulttimeout(timeout+0.5)
    responses = {}
    for _ in range(retries):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                             socket.IPPROTO_UDP)
        sock.bind((interface, 0))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.sendto(message.format(*group, st=service, mx=timeout), group)
        while True:
            try:
                response = SSDPResponse(sock.recv(1024))
                responses[response.location] = response
            except socket.timeout:
                break
        if responses:
            break
    return responses.values()
###############################################################################
# end Dan Krause library
###############################################################################


###############################################################################
#
# The following WeMo SOAP command set stuff is a lightly modified version of:
#     https://gist.github.com/pruppert/af7d38cb7b7ca75584ef
#
# I don't love the way this hard-codes the ports that the WeMo uses --
# seems like doing discovery would be better. However my previous
# implementation, which did not hardcode ports, failed once discovery
# failed.

class wemo:
    OFF_STATE = '0'
    ON_STATES = ['1', '8']
    ip = None
    ports = [49153, 49152, 49154, 49151, 49155]
    num_retries = 3             # retry wemo commands this many times

    def __init__(self, wemo_ip, wemo_port=None):
        self.ip = wemo_ip
        if wemo_port:
            self.ports = [wemo_port]

    def do(self, action_in):
        action = action_in.lower()

        if action == "on":
            result = self.on()
        elif action == "off":
            result = self.off()
        elif action == "toggle":
            result = self.toggle()
        elif action == "getstate" or action == "state":
            result = self.status()
        elif action == "getsignalstrength" or action == "signalstrength":
            result = self.signal()
        elif action == "getfriendlyname" or action == "getname":
            result = self.name()
        else:
            raise Exception("Unknown action %s" % action)

        return result

    def toggle(self):
        status = self.status()
        if status in self.ON_STATES:
            result = self.off()
            result = 'WeMo is now off.'
        elif status == self.OFF_STATE:
            result = self.on()
            result = 'WeMo is now on.'
        else:
            raise Exception("UnexpectedStatusResponse")
        return result

    def on(self):
        return self._send('Set', 'BinaryState', 1)

    def off(self):
        return self._send('Set', 'BinaryState', 0)

    def status(self):
        return self._send('Get', 'BinaryState')

    def name(self):
        return self._send('Get', 'FriendlyName')

    def signal(self):
        return self._send('Get', 'SignalStrength')

    def _get_header_xml(self, method, obj):
        method = method + obj
        return '"urn:Belkin:service:basicevent:1#%s"' % method

    def _get_body_xml(self, method, obj, value=0):
        method = method + obj
        s = '<u:{0} xmlns:u="urn:Belkin:service:basicevent:1"><{1}>'
        s += '{2}</{1}></u:{0}>'

        return s.format(method, obj, value)

    def _send(self, method, obj, value=None):
        body_xml = self._get_body_xml(method, obj, value)
        header_xml = self._get_header_xml(method, obj)
        for _ in range(self.num_retries):
            for port in self.ports:
                result = self._try_send(self.ip, port, body_xml, header_xml,
                                        obj)
                if result is not None:
                    self.ports = [port]
                    return result
            sleep(0.2)
        raise Exception("Timeout on all ports: {0}".format(self.ports))

    def _try_send(self, ip, port, body, header, data):
        url = 'http://{0}:{1}/upnp/control/basicevent1'.format(ip, port)
        hdrs = {'Content-type': 'text/xml; charset="utf-8"',
                'SOAPACTION': header}
        request_body = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<s:Envelope '
            'xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            '<s:Body>{0}</s:Body></s:Envelope>'
        )
        r = requests.post(url, headers=hdrs, data=request_body.format(body),
                          timeout=3.0)
        return self._extract(r.content, data)

    def _extract(self, response, name):
        exp = '<%s>(.*?)<\/%s>' % (name, name)
        g = re.search(exp, response)
        if g:
            return g.group(1)
        return response

###############################################################################
# end WeMo SOAP
###############################################################################


def wemo_discover(interface):
    devices = ssdp_discover("urn:Belkin:device:**", interface, 1, 6)

    for d in devices:
        m = re.match("http://([^:]*):([0-9]*)/.*", d.location)

        if not m:
            continue

        ip = m.group(1)
        port = m.group(2)

        try:
            name = wemo(ip, port).name()
            print("{0} (port {1}): {2}".format(ip, port, name))
        except Exception as e:
            print("{0} (port {1}): {2}".format(ip, port, str(e)))
            pass


if __name__ == '__main__':

    actions = ['On',
               'Off',
               'GetState',
               'GetSignalStrength',
               'GetFriendlyName',
               'Toggle']

    def usage():
        bn = os.path.basename(sys.argv[0])
        usage_msg = ("Usage: {exe_name} Discover [interface]\n"
                     "       {exe_name} IP_Address[:Port] <action>\n"
                     "\n")

        m = usage_msg.format(exe_name=bn)

        # a poor man's word-wrap of the last line
        acts = "<action> is one of {acts}".format(acts=", ".join(actions))
        m += '\n'.join(l.strip() for l in re.findall(r'.{1,78}(?:\s+|$)',
                                                     acts))
        print(m)

        sys.exit(1)

    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Incorrect number of arguments!")
        usage()

    if sys.argv[1].lower() == 'discover':
        if len(sys.argv) == 2:
            wemo_discover('0.0.0.0')
        elif len(sys.argv) == 3:
            wemo_discover(sys.argv[2])
        else:
            usage()
    else:
        m = re.match("(\d+\.\d+\.\d+\.\d+)(:[0-9]+)?$", sys.argv[1])
        if not m:
            print("Incorrect IP address: {0}".format(sys.argv[1]))
            usage()

        ip = m.group(1)
        port = m.group(2)
        if port:
            port = port[1:]

        action = sys.argv[2].lower()
        if action not in [a.lower() for a in actions]:
            print("Incorrect action: {0}".format(action))
            usage()

        switch = wemo(ip, port)
        try:
            print(switch.do(action))
        except Exception as e:
            sys.stderr.write("wemo %s %s: %s\n" % (ip, action, e))
            sys.exit(1)
