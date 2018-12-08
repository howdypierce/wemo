#!/usr/bin/env python3
#
# Control a Wemo device on your local network.
#
# Howdy Pierce, howdy@cardinalpeak.com
#


# Poor man's test plan. Note 'Family Room Lights' and 'Garage Lights'
# are real Belkin Wemos, and 'Bedroom Light' is a Fauxmo
#
#   ~/Code/wemo $ ./wemo.py discover
#   192.168.87.73:49915: Bedroom Light
#   192.168.87.73:49925: Night Light
#   192.168.87.73:49935: Bedroom Light Schedule
#   192.168.87.67:49153: Family Room Lights
#   192.168.87.134:49153: Kitchen Table
#   192.168.87.68:49153: Garage Lights
#   192.168.87.87:49153: Living Room Light
#   ~/Code/wemo $ ./wemo.py 'Family Room Lights' on
#   True
#   ~/Code/wemo $ ./wemo.py 192.168.87.67:49153 toggle
#   False
#   ~/Code/wemo $ ./wemo.py 192.168.87.67:49153 getstate
#   False
#   ~/Code/wemo $ ./wemo.py 192.168.87.67:49153 getfriendlyname
#   Family Room Lights
#   ~/Code/wemo $ ./wemo.py 192.168.87.67:49153 getsignalstrength
#   100
#   ~/Code/wemo $ ./wemo.py 192.168.87.73:49915 on
#   True
#   ~/Code/wemo $ ./wemo.py 192.168.87.73:49915 off
#   False
#   ~/Code/wemo $ ./wemo.py 192.168.87.73:49915 off
#   False
#   ~/Code/wemo $ ./wemo.py 192.168.87.73:49915 toggle
#   True
#   ~/Code/wemo $ ./wemo.py 192.168.87.73:49915 toggle
#   False
#   ~/Code/wemo $ ./wemo.py 192.168.87.73:49915 getstate
#   False
#   ~/Code/wemo $ ./wemo.py 192.168.87.73:49915 getfriendlyname
#   Bedroom Light
#   ~/Code/wemo $ ./wemo.py 192.168.87.73:49000 getfriendlyname  # wrong port
#   wemo 192.168.87.73 getstate: Timeout on ports ['49000']
#   ~/Code/wemo $ ./wemo.py 192.168.87.68 on   # automatic port finding
#   True
#   ~/Code/wemo $ ./wemo.py 192.168.87.68 off
#   False
#   ~/Code/wemo $ ./wemo.py 192.168.87.63 on   # non-responsive IP
#   wemo 192.168.87.63 on: Timeout on ports [49153, 49152, 49154, 49151, 49155]
#   ~/Code/wemo $ ./wemo.py Fred on
#   wemo Fred: Unable to find Wemo by name Fred


import re
import requests
import os
import socket
import selectors
import netifaces
from time import sleep
import sys


def interface_addrs(include_loopback: bool = False):
    """Get the IPv4 addresses for all configured interfaces on this host.

    Parameters
    ----------
    include_loopback
      Should loopback address be included in returned list?

    Returns
    -------
    Addresses are returned as a list of strings in dotted-decimal form.
    """

    addrs = [netifaces.ifaddresses(i) for i in netifaces.interfaces()]
    ret = [i['addr'] for a in addrs for i in a.get(netifaces.AF_INET, [])]

    if (not include_loopback):
        return [i for i in ret if i != '127.0.0.1']
    else:
        return ret


class SSDPDevice(object):
    """Utility class to represent a single SSDP endpoint"""

    @staticmethod
    def _parse_hdr(hdr: str, raw: bytes) -> str:
        """Parse the raw string for the given header, which is returned.
        If the header cannot be found, returns None."""
        try:
            ret = re.findall(f"(?im)^{hdr}: ?(.+)\r$", raw.decode('utf-8'))[0]
        except IndexError:
            ret = None
        return ret

    def __init__(self, raw):
        self.location = self._parse_hdr('location', raw)
        self.usn = self._parse_hdr('usn', raw)
        self.st = self._parse_hdr('st', raw)
        m = re.match(r"(?a)https*://([^:]+):(\d+)/.*", self.location)
        self.host = m.group(1) if m else ""
        self.port = m.group(2) if m else ""

    def __repr__(self):
        st = "<SSDPDevice({location}, {st}, {usn}, {host}, {port})>"
        return st.format(**self.__dict__)


def ssdp_discover(ssdp_st: str,
                  interfaces: list = None,
                  timeout: int = 2,
                  retries: int = 2):
    """Discover local SSDP devices over IPv4.

    Parameters
    ----------
    ssdp_st
      The SSDP Search Target as specified in the UPnP spec. Some
      values to try:
             ssdp:all              - theoretically everything, although
                Belkin Wemos don't respond to this (they should)
             upnp:rootdevice       - all root devices
             urn:Belkin:device:**  - all Wemos

    interfaces
      A list of interfaces to search. Default is to search all
      interfaces available to this host, except loopback.

    timeout
      How long to wait, in seconds, for each attempt.

    retries
      How many times to try the search. Default is 2. Note that the
      UPnP spec says ""Due to the unreliable nature of UDP, control
      points should send each M-SEARCH message more than once.'

    Unless an excpetion occurs, this function will return in
      ((timeout+0.1) * retries) seconds.

    Returns
    -------
    Returns a list of SSDPDevices
    """

    ipaddr = "239.255.255.250"
    port = 1900
    message = "\r\n".join([
        'M-SEARCH * HTTP/1.1',
        'HOST: {ip}:{port}',
        'MAN: "ssdp:discover"',
        'MX: {mx}',
        'ST: {st}',
        '',
        '']).format(ip=ipaddr, port=port, st=ssdp_st, mx=timeout)
    if interfaces is None:
        interfaces = interface_addrs()

    devices = {}
    for _ in range(retries):
        sel = selectors.DefaultSelector()
        for intf in interfaces:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                 socket.IPPROTO_UDP)
            sock.bind((intf, 0))
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.sendto(message.encode('utf-8'), (ipaddr, port))
            sock.setblocking(False)
            sel.register(sock, selectors.EVENT_READ)

        events = [None]
        while events:
            events = sel.select(timeout+0.1)
            for key, mask in events:
                dev = SSDPDevice(key.fileobj.recv(1024))
                devices[dev.usn] = dev

    return list(devices.values())


# The following Wemo class is a heavily modified version of:
#     https://gist.github.com/pruppert/af7d38cb7b7ca75584ef
class Wemo(object):
    """Control a Belkin Wemo device over the network.

    Also works with Fauxmo devices (https://github.com/n8henrie/fauxmo)
    """
    ip = None
    port = None
    name = None

    def __init__(self,
                 ip: str = None,
                 port: int = None,
                 name: str = None):
        """Initialize a Wemo instance.

        Parameters
        ----------
        ip
          The IP address of the Wemo. Optional, see below.
        port
          The port to use to control the Wemo. Optional; if not
          specified, the class will search the normal set of Belkin
          ports.
        name
          The friendly name of the Wemo. If specified, the class will
          attempt to perform network discovery to find a Wemo with the
          specified name.

        Caller must specify exactly one of IP or name.
        """
        if (ip is None and name is None):
            raise ValueError("Must specify either IP or name")
        self.ip = ip
        self.port = port
        self.name = name

    def do(self, action: str):
        """Perform one of the specified actions on the Wemo.
        Parameters
        ----------
        action
          One of 'on', 'off', 'toggle', 'getstate' or 'state',
          'getsignalstrength' or 'signalstrength', 'getfriendlyname'
          or 'getname'

        Returns
        -------
        Returns the value from calling the corresponding function.

        """
        action = action.lower()

        if action == "on":
            result = self.set_state(True)
        elif action == "off":
            result = self.set_state(False)
        elif action == "toggle":
            result = self.toggle()
        elif action == "getstate" or action == "state":
            result = self.get_state()
        elif action == "getsignalstrength" or action == "signalstrength":
            result = self.get_signal_strength()
        elif action == "getfriendlyname" or action == "getname":
            result = self.get_name()
        else:
            raise Exception("Unknown action %s" % action)

        return result

    def toggle(self):
        """Toggle the state of the Wemo.

        Returns
        -------
        If the command was successful, returns True or False,
        representing the new state of the Wemo.

        """
        return self.set_state(not self.get_state())

    @staticmethod
    def _state_to_bool(val: str):
        """Convert Wemo status string to Python bool.

        A Wemo returns its status as an integer string, either '1' or
        '8' for on, and '0' for off. Convert that to True/False.
        """
        if val in ['1', '8']:
            return True
        elif val == '0':
            return False
        else:
            raise Exception(f"UnexpectedStatusResponse: {val}")

    def set_state(self, state: bool):
        """Turn the Wemo to the indicated state."""
        if state:
            val = 1
        else:
            val = 0
        res = self._send('Set', 'BinaryState', val)
        # If the Wemo was already in the requested state, it returns
        # the string "Error". Way to ruin a nice idempotent function,
        # guys! If we get this string, just substitute what the Wemo
        # _should_ have sent!
        if res == 'Error':
            res = str(val)
        return self._state_to_bool(res)

    def get_state(self):
        """Get the Wemo's current state, on or off.

        Returns
        -------
        If the command was successul, returns a boolean representing
        the current state of the Wemo.

        """
        return self._state_to_bool(self._send('Get', 'BinaryState'))

    def get_name(self):
        """Get the friendly name of the Wemo."""
        if not self.name:
            self.name = self._send('Get', 'FriendlyName')
        return self.name

    def get_signal_strength(self):
        """Get the signal strength of the Wemo."""
        return self._send('Get', 'SignalStrength')

    def _get_header_xml(self, method, obj):
        return f'"urn:Belkin:service:basicevent:1#{method}{obj}"'

    def _get_body_xml(self, method, obj, value=0):
        return ('<u:{0}{1} xmlns:u="urn:Belkin:service:basicevent:1"><{1}>'
                '{2}</{1}></u:{0}{1}>').format(method, obj, value)

    def _send(self, method, obj, value=None):
        headers = {'Content-type': 'text/xml; charset="utf-8"',
                   'SOAPACTION': self._get_header_xml(method, obj)}
        body = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<s:Envelope '
            'xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            '<s:Body>{}</s:Body></s:Envelope>'
        ).format(self._get_body_xml(method, obj, value))

        result = self._try_send(headers, body)
        g = re.search(f"<{obj}>(.*?)</{obj}>", result)
        return g.group(1) if g else ""

    def _attempt_discovery(self):
        """Attempt discovery by name. Raise exception if not found."""
        if self.name is None:
            raise Exception("Can't discover with unknown name")
        w_list = find_wemos(search=self.name)
        if not w_list:
            raise Exception(f"Unable to find Wemo by name {self.name}")
        self.ip = w_list[0].ip
        self.port = w_list[0].port

    def _try_send(self, headers, body):
        if self.ip is None:
            self._attempt_discovery()
        if self.port:
            ports = [self.port]
        else:
            ports = [49153, 49152, 49154, 49151, 49155]
        for p in ports:
            url = f'http://{self.ip}:{p}/upnp/control/basicevent1'
            try:
                r = requests.post(url, headers=headers, data=body, timeout=3.0)
                return r.content.decode('utf-8')
            except (requests.ConnectTimeout, requests.ConnectionError) as e:
                if ("Errno 64" in f"{e}" and self.name):
                    # host is down - reset IP (to force discovery) and retry
                    self.ip = None
                    return self._try_send(headers, body)
                else:
                    pass
            sleep(0.2)
        raise Exception(f"Timeout on ports {ports}")


def find_wemos(interfaces=None, search=None):
    """Find Wemos on the network.

    Parameters
    ----------
    interfaces
       A list of interfaces on which to perform discovery. If not specified,
       all non-loopback IPv4 interfaces will be used
    search
       If specified, the list of returned devices will be limited to those
       whose friendly-names match this string

    Returns
    -------
    Returns a list of wemo objects that correspond to the discovered wemos
    """

    wemo_search_string = "urn:Belkin:device:**"

    # If we're looking for a particular Wemo, it makes sense to
    # iterate more times over shorter calls to ssdp_discover, because
    # as soon as we find the Wemo we're looking for, we can exit the
    # search. If, on the other hand, we are doing a general discovery
    # and not looking for a particular Wemo, we should make only one
    # call to ssdp_discover, but allow that call to have a relatively
    # longer timeout and number of retries.
    if search:
        search = search.lower().strip()
        search_strategy = [(1, 1), (1, 1), (3, 1)]
    else:
        search_strategy = [(2, 3)]

    rl = {}
    for t_out, retry in search_strategy:
        devices = ssdp_discover(wemo_search_string, interfaces, t_out, retry)

        for d in devices:
            if (d.host, d.port) in rl:
                continue

            try:
                wm = Wemo(d.host, d.port)
            except Exception:
                continue

            if search and wm.get_name().lower().strip() != search:
                continue

            rl[(d.host, d.port)] = wm

        if search and rl:
            break

    return list(rl.values())


def wemo_discover(interfaces=None):
    """Print the IP address, port, and friendly name for all Wemos found."""
    for wm in find_wemos(interfaces):
        print(f"{wm.ip}:{wm.port}: {wm.get_name()}")


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
                     "       {exe_name} IP_Address[:Port] Action\n"
                     "       {exe_name} Friendly_Name Action\n"
                     "\n")

        m = usage_msg.format(exe_name=bn)

        # a poor man's word-wrap of the last line
        acts = "Action is one of {acts}".format(acts=", ".join(actions))
        m += '\n'.join(l.strip() for l in re.findall(r'.{1,78}(?:\s+|$)',
                                                     acts))
        print(m)

        sys.exit(1)

    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Incorrect number of arguments!")
        usage()

    if sys.argv[1].lower() == 'discover':
        if len(sys.argv) == 2:
            wemo_discover()
        elif len(sys.argv) == 3:
            wemo_discover([sys.argv[2]])
        else:
            usage()
        sys.exit(0)

    if len(sys.argv) != 3:
        usage()

    action = sys.argv[2].lower()
    if action not in [a.lower() for a in actions]:
        print(f"Incorrect action: {action}")
        usage()

    m = re.match(r"(\d+\.\d+\.\d+\.\d+)(:[0-9]+)?$", sys.argv[1])
    if m:
        # User specified IP & port
        ip = m.group(1)
        port = m.group(2)
        if port:
            port = port[1:]
        switch = Wemo(ip, port)
    else:
        # User specified wemo by name
        switch = Wemo(name=sys.argv[1])

    try:
        print(switch.do(action))
    except Exception as e:
        sys.stderr.write(f"wemo {sys.argv[1]}: {e}\n")
        sys.exit(1)

    sys.exit(0)
