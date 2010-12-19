import threading, hashlib, time, socket, sys, random, SocketServer

def makeChallenge():
    al = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join( [ random.choice(al) for i in range(32) ] )

def sendLine( sock, line ):
    out = line + "\n"
    sent = 0
    while sent < len(out):
        rv = sock.send( out[sent:] )
        sent += rv

def getLine( sock ):
    data = []
    while not data or not ("\n" in data[-1]):
        rv = sock.recv( 1024 )
        if rv:
            data.append( rv )
    return "".join( data ).strip()

class UniversalPassword:
    def __init__(self, pw):
        self.pw = pw
    def __getitem__(self, name):
        return self.pw


def report(name, password, server, port):
    sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
    sock.connect( (server,port) )
    challenge = getLine( sock )
    response = hashlib.sha1( name + challenge + password ).hexdigest()
    sendLine( sock, ":".join( [name, response] ) )

def serve( passwords, interval, hostname, port, filename = None ):
    lock = threading.Lock()
    locations = {}
    class TcpHandler ( SocketServer.BaseRequestHandler ):
        def handle(self):
            data = []
            challenge = makeChallenge()
            sendLine( self.request, challenge )
            name,answer = getLine( self.request ).split(":")
            password = passwords[ name ]
            correct = hashlib.sha1( name + challenge + password ).hexdigest()
            if correct == answer:
                lock.acquire()
                locations[ name ] = time.time(), self.client_address[0]
                lock.release()
    class ThreadedTcpServer ( SocketServer.ThreadingMixIn, SocketServer.TCPServer ):
        pass
    server = ThreadedTcpServer( (hostname, port), TcpHandler )
    server_thread = threading.Thread( target=server.serve_forever )
    server_thread.setDaemon( True )
    server_thread.start()
    t0 = None
    while True:
        if (not t0) or ((time.time() - t0) > interval):
            lock.acquire()
            if filename:
                f = open( filename, "w" )
            else:
                f = sys.stdout
            t0 = time.time()
            for name, (t,address) in locations.items():
                print>>f, "%s:%d:%s" % ( name, int(t0 - t), address )
            if filename:
                f.close()
            lock.release()
        time.sleep( 1.0 )

if __name__ == '__main__':
    from optparse import OptionParser
    parser = OptionParser()
    parser.add_option( "-P", "--password", dest="password",
                       help="use the password PASSWORD", metavar="PASSWORD" )
    parser.add_option( "-i", "--interval", dest="interval",
                       default=60.0,
                       help="set report interval INTERVAL in seconds",
                       metavar="INTERVAL" )
    parser.add_option( "-p", "--port", dest="port",
                       default=31589,
                       help="set the PORT",
                       metavar="PORT" )
    parser.add_option( "-H", "--host", dest="host", default = "localhost",
                       help="set the host name to HOST",
                       metavar="HOST" )
    parser.add_option( "-s", "--serve", dest="serve", default = False,
                       action="store_true",
                       help="run in server mode" )
    parser.add_option( "-n", "--name", dest="name", default = None,
                       help="set the NAME",
                       metavar="NAME" )
    parser.add_option( "-O", "--output", dest="filename", default = None,
                       help="reports to FILENAME",
                       metavar="FILENAME" )
    options, args = parser.parse_args()
    if options.serve:
        serve( UniversalPassword( options.password ),
               int( options.interval ),
               options.host,
               int( options.port ),
               options.filename )
    else:
        report( options.name, options.password, options.host, int( options.port ) )
