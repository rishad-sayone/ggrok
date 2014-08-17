
from gevent.monkey import patch_all
patch_all()

import json
import socket
import struct
import ssl
import logging
import gevent
import uuid


class BaseConnection(object):

    def __init__(self, client_id='', hostname='96.126.125.171', port=443):
        self.client_id = client_id
        self.hostname = hostname
        self.port = port

        self.logger = logging.getLogger(repr(self))

    def _recv_one(self):
        length = ''
        while len(length) < 8:
            length += self.socket.recv(8-len(length))
        length =  struct.unpack("L", length)[0]

        self.logger.debug("Reading message with length: %d" % length)

        payload = ''
        while len(payload) < length:
            payload += self.socket.recv(length-len(payload))

        self.logger.debug("Read message %s" % payload)

        return json.loads(payload)

    def _send(self, msg, payload):
        buffer = json.dumps({"Type": msg, "Payload": payload})
        self.logger.debug("Writing message: %s" % buffer)
        self.socket.send(struct.pack('L', len(buffer)))
        self.socket.send(buffer)

    def connect(self):
        try:
            hostname = socket.gethostbyname(self.hostname)
        except socket.gaierror:
            raise ConnectionError('%r not found' % self.hostname)

        _socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket = gevent.ssl.SSLSocket(_socket, ssl_version=ssl.PROTOCOL_SSLv3)
        self.socket.connect((hostname, self.port))

        self.logger.debug("New connection to: %s:%d" % (self.hostname, self.port))


class Proxy(BaseConnection):

    def __init__(self, handler, **kwargs):
        super(Proxy, self).__init__(**kwargs)
        self.handler = handler

    def wait_for_start(self):
        self.connect()

        self._send("RegProxy", {
            "ClientId": self.client_id,
        })

        self.logger.debug("Waiting for proxy to be started")

        reply = self._recv_one()
        if reply["Type"] != "StartProxy":
            raise ConnectionError("Expected 'StartProxy' but got '%s'" % reply["Type"])

        self.logger.debug("Invoking handler for %r (client=%r)" % (reply["Payload"]["Url"], reply["Payload"]["ClientAddr"]))

        self.handler(self.socket, reply["Payload"]["Url"], reply["Payload"]["ClientAddr"])


class Control(BaseConnection):

    def __init__(self, **kwargs):
        super(Control, self).__init__(**kwargs)
        self._tunnels = {}
        self._handlers = {}

    def connect(self, user='', password=''):
        super(Control, self).connect()

        self._send("Auth", {
            "Version": "2",
            "MmVersion": "1.7",
            "User": user,
            "Password": password,
            "OS": "darwin",
            "Arch": "amd64",
            "ClientId": self.client_id,
        })

        reply = self._recv_one()
        if reply["Type"] != "AuthResp":
            raise ConnectionError("Expected 'AuthResp' but got '%s'" % reply["Type"])

        if reply["Payload"]["Error"] != '':
            raise ConnectionError(reply["Payload"]["Error"])

        self.client_id = reply["Payload"]["ClientId"]

        gevent.spawn(self._ping_loop)

    def _ping_loop(self):
        while True:
            gevent.sleep(10)
            self._send("Ping", {})

    def add_tunnel(self, protocol, handler):
        reqid = str(uuid.uuid4()).replace("-", "")[:16]
        self._handlers[reqid] = handler

        self._send("ReqTunnel", {
            "Protocol": protocol,
            "ReqId": reqid,
            "Hostname": "",
            "Subdomain": "",
            "HttpAuth": "",
            "RemotePort": 0,
        })

    def _loop(self):
        while True:
            self.logger.debug("Waiting to read message")
            msg = self._recv_one()
            handler = getattr(self, "on_" + msg["Type"].lower(), None)
            if handler:
                handler(msg['Payload'])

    def on_ping(self, payload):
        self._send("Pong")

    def on_reqproxy(self, payload):
        # The server will send a ReqProxy message when it wants the client to open up a new Proxy type connection
        p = Proxy(
            client_id=self.client_id,
            hostname=self.hostname,
            port=self.port,
            handler=self.on_startproxy,
        )
        gevent.spawn(p.wait_for_start)

    def on_newtunnel(self, payload):
        # The server will send a NewTunnel message when it has finished settin up a new end point for us
        # Maybe multiple of these for a signal add_tunnel - can set up http/https at same time

        if payload["Error"] != '':
            self.logger.error("%s/%s: %s" % (payload['Url'], payload['ReqId'], payload['Error']))
            return

        if payload['ReqId'] not in self._handlers:
            self.logger.error("Got tunnel but couldn't find req %s" % payload['ReqId'])
            return

        self._tunnels[payload['Url']] = self._handlers[payload['ReqId']] 

    def on_startproxy(self, socket, url, client_address):
        # This is called by a Proxy when it has been told to service a request.
        try:
            handler = self._tunnels[url]
        except KeyError:
            self.logger.error("Couldn't find a handler for %r" % url)
            socket.close()
            return

        handler(socket, client_address)


def handler(socket, client_address):
    socket.send("\n".join([
        "HTTP/1.0 200 OK",
        "Content-Type: text/html; charset=UTF-8",
        "Connection: close",
        "",
        "<html><head><title>Hello!</title></head><body>Hello!</body></html>",
        ]))
    socket.close()


logging.basicConfig(level=logging.DEBUG)

c = Control()
c.connect()
c.add_tunnel("http+https", handler)
c._loop()
