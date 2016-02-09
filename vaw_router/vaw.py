#!/usr/bin/env python

'''
VAW is a VNC with WebSocket proxy support for "wss://" encryption.
Licensed under LGPL version 3 (see ../LICENSE)

This file orginaly made by
Joel Martin (https://github.com/kanaka/websockify)
Modified by Sebastien CAPS for the VAW Project

You can make a cert/key with openssl using:
openssl req -new -x509 -days 365 -nodes -out self.pem -keyout self.pem
as taken from http://docs.python.org/dev/library/ssl.html#certificates

'''
import json, random, string
import signal, socket, optparse, time, os, sys, subprocess, logging, errno
try:    from socketserver import ForkingMixIn
except: from SocketServer import ForkingMixIn
try:    from http.server import HTTPServer
except: from BaseHTTPServer import HTTPServer
import select
from vaw_router import vaw_websocket
try:
    from urllib.parse import parse_qs, urlparse
except:
    from cgi import parse_qs
    from urlparse import urlparse

from multiprocessing import Pipe
from multiprocessing import reduction
from multiprocessing import Queue
from multiprocessing import Manager

def id_gen():
    return str(random.randrange(100000000, 999999999, 2))

class ProxyRequestHandler(vaw_websocket.WebSocketRequestHandler):

    def new_websocket_client(self, path=None):
        """
        Called after a new WebSocket connection has been established.
        """
        # Checking for a token is done in validate_connection()
        _id = None
        msg = None
        try:
            if path != None and path != '/' and path.index("-") != -1:
                # remove first / and get mode(client or manager)
                mode      = str(path[1:path.index("-")])

                # Now extract id & pw
                tmp       = str(path[path.index("-")+1:])
                wanted_id = str(tmp[:tmp.index("-")])
                wanted_pw = str(tmp[tmp.index("-")+1:])

                # Clear tmp
                del tmp

                # Create a queue for any new client/manager
                manager = Manager()

                if mode == "manager":
                    if wanted_pw == self.session[wanted_id]["pw"]:
                        # Generate the id of the manager
                        _id = id_gen()

                        self.wanted_id = wanted_id

                        if self.pipe == None:
                            reduced = self.session[wanted_id]["pipe"]
                            self.pipe = reduced[0](*reduced[1])

                        self.connected = True
                        self.pipe.send('{ "vnc": "connect" }')
                        
                        # Init manager queue in the session
                        self.session[_id]= { "mode": "manager", "id": _id, "wanted_id": wanted_id, "wanted_pw": wanted_pw, "authenticated": True  }

                        msg = "New manager id: %s wanted client id: %s" % (_id, wanted_id)
                    else:
                        _id = None
                        self.session[_id] = None 

                elif mode == "client":
                    # Use client provided id
                    _id = wanted_id

                    # Since we are a client we dont have a wanted id
                    self.wanted_id = None

                    # Waiting for manager
                    self.connected = False

                    self.pipe, manager_conn = Pipe()
                    try:

                        # Init the client queue in the session
                        self.session[wanted_id]= { "mode": "client", "id": wanted_id, "pw": wanted_pw, "authenticated": True, "pipe": reduction.reduce_connection(manager_conn) }
                    except:
                        print "pipe error"
                        print sys.exc_type,sys.exc_value
                
                    msg = "New client id: %s" % _id
                else:
                    msg = "Error no client/manager mode detected !!!"
                    self.send_close()

                if msg != None:
                    # add log entry
                    self.log_message(msg)
        except:
            print "Error in new_websocket_client()"
            print sys.exc_type, sys.exc_value
            del self.session[_id]
            try:
                # if exception occured the close socket
                self.send_close()
            except:
                pass

        # Start proxying
        try:
            if _id != None:
                self.vawrouter(_id)
            else:
                del self.session[_id]
                self.send_close()
        except:
            del self.session[_id]
            self.send_close()
            print "Error in vaw router"
            print sys.exc_type,sys.exc_value

    def getManagerIdByClientId(self, client_id):
        for manager_id, data in self.session.items():
            if ("wanted_id" in self.session[manager_id] and self.session[manager_id]["wanted_id"] == client_id):
                if(self.session[manager_id]["authenticated"] == True):
                    return str(manager_id)
        return False

    def vawrouter(self,_id):
        """
        Route client data to the manager socket.
        """
        cqueue = []
        c_pend = 0
        rlist = [self.request]

        if self.server.heartbeat:
            now = time.time()
            self.heartbeat = now + self.server.heartbeat
        else:
            self.heartbeat = None

        if self.heartbeat is not None:
            now = time.time()
            if now > self.heartbeat:
                self.heartbeat = now + self.server.heartbeat
                self.send_ping()

        self.request.settimeout(0.0045)
        self.request.setblocking(0)

        while True:
            try:
                # Receive client data, decode it, and queue for target
                bufs, closed = self.recv_frames()
            except:
                closed = False
                bufs = []

            if closed:
                 del self.session[_id]
                 self.log_message("Connection closed")
            else:
                # Trigger push
                self.push(_id)
                if not self.connected:
                    # Save CPU while waiting for manager connexion
                    time.sleep(0.3)
                for buff in bufs:
                        try:
                            if self.connected:
                                self.pipe.send(buff)
                            elif self.pipe != None and self.wanted_id != False or ( self.wanted_id in self.session and self.wanted_id != None ):
                                self.connected = True
                                self.pipe.send(buff)
                            elif self.session[_id]["mode"] == "client":
                                self.wanted_id = self.getManagerIdByClientId(_id)
                                if self.wanted_id != False:
                                    self.connected = True
                                    self.pipe.send(buff)
                                else:
                                    del self.session[_id]
                                    self.log_message("Manager has gone, closing client connection.")
                                    self.send_close()
                            elif self.session[_id]["mode"] == "manager" and self.session[_id]["authenticated"] == True:
                                # get pipe of the wanted client
                                if self.wanted_id in self.session:
                                    if self.pipe == None:
                                         reduced = self.session[self.wanted_id]["pipe"]
                                         self.pipe = reduced[0](*reduced[1])
                                    self.connected = True
                                    self.pipe.send(buff)
                                else:
                                    del self.session[_id]
                                    self.log_message("Client has gone, closing manager connection.")
                                    self.send_close()
                            else:
                                self.log_message("Error")
                                del self.session[_id]
                                self.pipe = None
                                self.send_close()
                        except:
                            self.send_close()
                            del self.session[_id]
                            self.pipe = None
                            print sys.exc_type, sys.exc_value

    def push(self, _id):
        if self.pipe != None:
          try:
            if self.pipe.poll(0.0045):
                qdata = ""
                qdata = self.pipe.recv()
                self.send_frames([qdata])
          except:
            print "Exception in push"
            del self.session[_id]
            self.send_close()

class WebSocketProxy(vaw_websocket.WebSocketServer):
    """
    Proxy traffic to and from a WebSockets client to a normal TCP
    socket server target. All traffic to/from the client is base64
    encoded/decoded to allow binary data to be sent/received to/from
    the target.
    """

    buffer_size = 65536

    def __init__(self, RequestHandlerClass=ProxyRequestHandler, *args, **kwargs):
        # Save off proxy specific options
        self.target_host    = kwargs.pop('target_host', None)
        self.target_port    = kwargs.pop('target_port', None)
        self.wrap_cmd       = kwargs.pop('wrap_cmd', None)
        self.wrap_mode      = kwargs.pop('wrap_mode', None)
        self.unix_target    = kwargs.pop('unix_target', None)
        self.ssl_target     = kwargs.pop('ssl_target', None)
        self.heartbeat      = kwargs.pop('heartbeat', None)

        self.token_plugin   = kwargs.pop('token_plugin', None)
        self.auth_plugin    = kwargs.pop('auth_plugin', None)

        self.session        = kwargs.pop('session', None)

        # Last 3 timestamps command was run
        self.wrap_times    = [0, 0, 0]

        if self.wrap_cmd:
            wsdir = os.path.dirname(sys.argv[0])
            rebinder_path = [os.path.join(wsdir, "..", "lib"),
                             os.path.join(wsdir, "..", "lib", "websockify"),
                             wsdir]
            self.rebinder = None

            for rdir in rebinder_path:
                rpath = os.path.join(rdir, "rebind.so")
                if os.path.exists(rpath):
                    self.rebinder = rpath
                    break

            if not self.rebinder:
                raise Exception("rebind.so not found, perhaps you need to run make")
            self.rebinder = os.path.abspath(self.rebinder)

            self.target_host = "127.0.0.1"  # Loopback
            # Find a free high port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(('', 0))
            self.target_port = sock.getsockname()[1]
            sock.close()

            os.environ.update({
                "LD_PRELOAD": self.rebinder,
                "REBIND_OLD_PORT": str(kwargs['listen_port']),
                "REBIND_NEW_PORT": str(self.target_port)})

        vaw_websocket.WebSocketServer.__init__(self, RequestHandlerClass, *args, **kwargs)

    def run_wrap_cmd(self):
        self.msg("Starting '%s'", " ".join(self.wrap_cmd))
        self.wrap_times.append(time.time())
        self.wrap_times.pop(0)
        self.cmd = subprocess.Popen(
                self.wrap_cmd, env=os.environ, preexec_fn=_subprocess_setup)
        self.spawn_message = True

    def started(self):
        """
        Called after Websockets server startup (i.e. after daemonize)
        """
        # Need to call wrapped command after daemonization so we can
        # know when the wrapped command exits
        if self.wrap_cmd:
            dst_string = "'%s' (port %s)" % (" ".join(self.wrap_cmd), self.target_port)
        elif self.unix_target:
            dst_string = self.unix_target
        else:
            dst_string = "%s:%s" % (self.target_host, self.target_port)

        if self.ssl_target:
            msg += " (using SSL)"

        if self.wrap_cmd:
            self.run_wrap_cmd()

    def poll(self):
        # If we are wrapping a command, check it's status

        if self.wrap_cmd and self.cmd:
            ret = self.cmd.poll()
            if ret != None:
                self.vmsg("Wrapped command exited (or daemon). Returned %s" % ret)
                self.cmd = None

        if self.wrap_cmd and self.cmd == None:
            # Response to wrapped command being gone
            if self.wrap_mode == "ignore":
                pass
            elif self.wrap_mode == "exit":
                sys.exit(ret)
            elif self.wrap_mode == "respawn":
                now = time.time()
                avg = sum(self.wrap_times)/len(self.wrap_times)
                if (now - avg) < 10:
                    # 3 times in the last 10 seconds
                    if self.spawn_message:
                        self.warn("Command respawning too fast")
                        self.spawn_message = False
                else:
                    self.run_wrap_cmd()


def _subprocess_setup():
    # Python installs a SIGPIPE handler by default. This is usually not what
    # non-Python successfulbprocesses expect.
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)


def logger_init():
    logger = logging.getLogger(WebSocketProxy.log_prefix)
    logger.propagate = False
    logger.setLevel(logging.INFO)
    h = logging.StreamHandler()
    h.setLevel(logging.DEBUG)
    h.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(h)


def router_init():
    logger_init()

    usage = "\n    %prog [options]"
    usage += " [source_addr:]source_port"
    parser = optparse.OptionParser(usage=usage)
    parser.add_option("--verbose", "-v", action="store_true",
            help="verbose messages")
    parser.add_option("--daemon", "-D",
            dest="daemon", action="store_true",
            help="become a daemon (background process)")
    parser.add_option("--cert", default="self.pem",
            help="SSL certificate file")
    parser.add_option("--key", default=None,
            help="SSL key file (if separate from cert)")
    parser.add_option("--ssl-only", action="store_true",
            help="disallow non-encrypted client connections")
    parser.add_option("--ssl-target", action="store_true",
            help="connect to SSL target as SSL client")
    parser.add_option("--web", default=None, metavar="DIR",
            help="run webserver on same port. Serve files from DIR.")
    parser.add_option("--libserver", action="store_true",
            help="use Python library SocketServer engine")
    parser.add_option("--auto-pong", action="store_true",
            help="Automatically respond to ping frames with a pong")
    parser.add_option("--heartbeat", type=int, default=0,
            help="send a ping to the client every HEARTBEAT seconds")
    parser.add_option("--log-file", metavar="FILE",
            dest="log_file",
            help="File where logs will be saved")

    (opts, args) = parser.parse_args()

    if opts.log_file:
        opts.log_file = os.path.abspath(opts.log_file)
        handler = logging.FileHandler(opts.log_file)
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logging.getLogger(WebSocketProxy.log_prefix).addHandler(handler)

    del opts.log_file

    if opts.verbose:
        logging.getLogger(WebSocketProxy.log_prefix).setLevel(logging.DEBUG)


    if not vaw_websocket.ssl and opts.ssl_target:
        parser.error("SSL target requested and Python SSL module not loaded.");

    if opts.ssl_only and not os.path.exists(opts.cert):
        parser.error("SSL only and %s not found" % opts.cert)

    # Parse host:port and convert ports to numbers
    if args[0].count(':') > 0:
        opts.listen_host, opts.listen_port = args[0].rsplit(':', 1)
        opts.listen_host = opts.listen_host.strip('[]')
    else:
        opts.listen_host, opts.listen_port = '', args[0]

    try:    opts.listen_port = int(opts.listen_port)
    except: parser.error("Error parsing listen port")

    manager = Manager()

    opts.session = manager.dict()

    # Create and start the WebSockets proxy
    libserver = opts.libserver
    del opts.libserver
    if libserver:
        # Use standard Python SocketServer framework
        server = LibProxyServer(**opts.__dict__)
        server.serve_forever()
    else:
        # Use internal service framework
        server = WebSocketProxy(**opts.__dict__)
        server.start_server()

class LibProxyServer(ForkingMixIn, HTTPServer):
    """
    Just like WebSocketProxy, but uses standard Python SocketServer
    framework.
    """

    def __init__(self, RequestHandlerClass=ProxyRequestHandler, **kwargs):
        # Save off proxy specific options
        self.wrap_cmd       = kwargs.pop('wrap_cmd', None)
        self.wrap_mode      = kwargs.pop('wrap_mode', None)
        self.ssl_target     = kwargs.pop('ssl_target', None)
        self.heartbeat      = kwargs.pop('heartbeat', None)
        self.session        = kwargs.pop('session', None)

        self.token_plugin = None
        self.auth_plugin = None
        self.daemon = False

        # Server configuration
        listen_host    = kwargs.pop('listen_host', '')
        listen_port    = kwargs.pop('listen_port', None)
        web            = kwargs.pop('web', '')

        # Configuration affecting base request handler
        self.only_upgrade   = not web
        self.verbose   = kwargs.pop('verbose', False)
        record = kwargs.pop('record', '')
        if record:
            self.record = os.path.abspath(record)
        self.run_once  = kwargs.pop('run_once', False)
        self.handler_id = 0

        for arg in kwargs.keys():
            print("warning: option %s ignored when using --libserver" % arg)

        if web:
            os.chdir(web)

        HTTPServer.__init__(self, (listen_host, listen_port),
                            RequestHandlerClass)


    def process_request(self, request, client_address):
        """Override process_request to implement a counter"""
        self.handler_id += 1
        ForkingMixIn.process_request(self, request, client_address)


if __name__ == '__main__':
    router_init()
