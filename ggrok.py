import gevent
import json
import logging
import socket
import struct
import ssl
import uuid

from gevent import queue, pool
from gevent.monkey import patch_all

patch_all()


class SocketWrapper(object):

    def __init__(self, socket):
        self.socket = socket
        self.logger = logging.getLogger(self.__module__)

    @classmethod
    def connect(cls, hostname, port):
        try:
            hostname = socket.gethostbyname(hostname)
        except socket.gaierror:
            raise ConnectionError('%r not found' % hostname)

        bare_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = ssl.wrap_socket(bare_sock, ssl_version=ssl.PROTOCOL_SSLv3)
        ssl_sock.connect((hostname, port))

        sock = cls(ssl_sock)
        sock.logger.debug("New connection to %s:%d" % (hostname, port))
        return sock

    def recv(self):
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

    def send(self, msg, payload):
        buffer = json.dumps({"Type": msg, "Payload": payload})
        self.logger.debug("Writing message: %s" % buffer)
        self.socket.send(struct.pack('L', len(buffer)))
        self.socket.send(buffer)


class Control(object):

    def __init__(self, client_id='', hostname='96.126.125.171', port=443):
        self.client_id = client_id
        self.hostname = hostname
        self.port = port

        self.socket = None
        self._tunnels = {}
        self._handlers = {}

        self._group = pool.Group()
        self._outbox = queue.Queue()

        self.logger = logging.getLogger(self.__module__)

    def connect(self, user='', password=''):
        self.socket = SocketWrapper.connect(self.hostname, self.port)

        self.socket.send("Auth", {
            "Version": "2",
            "MmVersion": "1.7",
            "User": user,
            "Password": password,
            "OS": "darwin",
            "Arch": "amd64",
            "ClientId": self.client_id,
        })

        reply = self.socket.recv()
        if reply["Type"] != "AuthResp":
            raise ConnectionError("Expected 'AuthResp' but got '%s'" % reply["Type"])

        if reply["Payload"]["Error"] != '':
            raise ConnectionError(reply["Payload"]["Error"])

        self.client_id = reply["Payload"]["ClientId"]

        self._group.spawn(self._inbox_loop)
        self._group.spawn(self._outbox_loop)
        self._group.spawn(self._ping_loop)

    def send(self, msg_type, payload=None):
        self.logger.debug("Queued message type %s: %s" % (msg_type, payload))
        self._outbox.put((msg_type, payload or {}))

    def add_tunnel(self, protocol, handler):
        reqid = str(uuid.uuid4()).replace("-", "")[:16]
        self._handlers[reqid] = handler

        self.send("ReqTunnel", {
            "Protocol": protocol,
            "ReqId": reqid,
            "Hostname": "",
            "Subdomain": "",
            "HttpAuth": "",
            "RemotePort": 0,
        })

    def _outbox_loop(self):
        while True:
            self.logger.debug("Waiting for outbox...")
            msg_type, payload = self._outbox.get()
            self.socket.send(msg_type, payload)

    def _ping_loop(self):
        while True:
            self.logger.debug("Ping loop sleeping...")
            gevent.sleep(15)
            self.send("Ping")

    def _inbox_loop(self):
        while True:
            self.logger.debug("Waiting to read message")
            msg = self.socket.recv()
            handler = getattr(self, "on_%s" % msg["Type"].lower(), None)
            if handler:
                handler(msg['Payload'])

    def on_ping(self, payload):
        self.send("Pong")

    def on_reqproxy(self, payload):
        # The server will send a ReqProxy message when it wants the client to open up a new Proxy type connection
        self.logger.debug("Setting up new proxy connection")
        self._group.spawn(self.setup_proxy_connection)

    def setup_proxy_connection(self):
        socket = SocketWrapper.connect(self.hostname, self.port)
        socket.send("RegProxy", {
            "ClientId": self.client_id,
        })

        self.logger.debug("Waiting for proxy to be started")

        reply = socket.recv()
        if reply["Type"] != "StartProxy":
            raise ConnectionError("Expected 'StartProxy' but got '%s'" % reply["Type"])

        url = reply["Payload"]["Url"]
        client_addr = reply["Payload"]["ClientAddr"]

        try:
            handler = self._tunnels[url]
        except KeyError:
            self.logger.error("Couldn't find a handler for %r" % url)
            socket.socket.close()
            return

        self.logger.debug("Invoking handler for %r (client=%r)" % (url, client_addr))

        handler(socket.socket, client_addr)

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
        self.logger.debug("Attached handler to '%s'" % payload['Url'])

    def join(self):
        return self._group.join()


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
c.join()
