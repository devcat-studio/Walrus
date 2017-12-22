#!/usr/bin/env python3
import sys
import http.server
import socketserver
import signal
import shutil
import json
import walrus

if sys.maxsize > 2**32:
    dll_path = r'..\x64\Release.dll\Walrus.dll'
else:
    dll_path = r'..\x86\Release.dll\Walrus.dll'
print('*** using a dll', dll_path, file=sys.stderr)

# global database
WALRUS = walrus.Walrus(realm=b'SAMPLE REALM', dll_path=dll_path)
WALRUS.rehash_interval = 10 # as an example
WALRUS.rehash()
KEYPAIRS = WALRUS.keypairs # for logging
USERS = {}

class Handler(http.server.BaseHTTPRequestHandler):
    def content(self):
        clen = int(self.headers['Content-Length'])
        data = self.rfile.read(clen)
        if len(data) != clen: raise RuntimeError('short read')
        return data

    def reply(self, data, status=200, cache=True):
        self.send_response(status)
        self.send_header('Content-Length', len(data))
        if not cache:
            self.send_header('Cache-Control', 'no-cache')
        self.end_headers()
        self.wfile.write(data)

    def file(self, path):
        try: f = open(path, 'rb')
        except Exception: return self.reply(b'Not found', status=404)
        with f:
            self.send_response(200)
            f.seek(0, 2)
            self.send_header('Content-Length', f.tell())
            f.seek(0)
            self.end_headers()
            shutil.copyfileobj(f, self.wfile)

    def do_GET(self):
        if self.path == '/':
            return self.file('index.html')
        elif self.path == '/Walrus.standalone.min.js':
            return self.file(r'..\Walrus.TypeScript\bin\Walrus.standalone.min.js')
        elif self.path == '/Walrus.standalone.min.js.map':
            return self.file(r'..\Walrus.TypeScript\bin\Walrus.standalone.min.js.map')
        else:
            return self.reply(b'Not found', status=404)

    def do_POST(self):
        global KEYPAIRS

        if self.path == '/params':
            WALRUS.rehash()
            keypairs = WALRUS.keypairs
            if keypairs != KEYPAIRS:
                print('*** rehashed server keypairs:', keypairs, file=sys.stderr)
                KEYPAIRS = keypairs
            return self.reply(WALRUS.params, cache=False)

        elif self.path == '/change-cost':
            try:
                newcost = WALRUS.set_stretch_cost(int(self.content(), 16))
            except walrus.WalrusError:
                return self.reply(b'')
            else:
                print('*** storage cost set to:', hex(newcost))
                return self.reply(('%08x' % newcost).encode('ascii'))

        elif self.path == '/signin':
            user, secret = json.loads(self.content())
            secret = WALRUS.decode_secret(user.encode('utf-8'), secret.encode('ascii'))
            try:
                stored_secret, comment = USERS[user]
            except KeyError:
                stored_secret = comment = None
            try:
                if secret.verify(stored_secret): # stretch params updated
                    new_secret = secret.export()
                    USERS[user] = (new_secret, comment)
                    print('*** updated stored secret for', repr(user), file=sys.stderr)
                    print('    from:', stored_secret, file=sys.stderr)
                    print('    to:  ', new_secret, file=sys.stderr)
            except walrus.WalrusError:
                return self.reply(b'USER_PASS_COMBINATION_MISMATCH', status=403)
            result = secret.make_result(comment.encode('utf-8'))
            return self.reply(result)

        elif self.path == '/signup':
            user, secret, comment = json.loads(self.content())
            if user in USERS:
                return self.reply(b'USER_ALREADY_EXISTS')
            secret = WALRUS.decode_secret(user.encode('utf-8'), secret.encode('ascii'))
            USERS[user] = (secret.export(), comment)
            print('*** added stored secret for', repr(user), file=sys.stderr)
            return self.reply(b'OK')

        elif self.path == '/users':
            data = sorted((u, s.decode('ascii'), c) for u, (s, c) in USERS.items())
            return self.reply(json.dumps(data).encode('utf-8'))

        else:
            return self.reply(b'Not supported method', status=501)

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
with socketserver.TCPServer(('', PORT), Handler) as httpd:
    print('*** listening from %s:%d' % httpd.server_address)
    httpd.serve_forever()

