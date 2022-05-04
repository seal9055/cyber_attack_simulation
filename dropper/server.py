from http.server import HTTPServer, BaseHTTPRequestHandler

class Serv(BaseHTTPRequestHandler):

    def do_GET(self):
        print(self.path)
        if self.path == '/malware.bin':
            #self.path = '/test.txt'
            self.path = '/hello_world'
        try:
            file_to_open = open(self.path[1:], 'rb').read()
            self.send_response(200)
        except Exception as e:
            print(e)
            file_to_open = "File not found"
            self.send_response(404)
        self.end_headers()
        self.wfile.write(file_to_open)

def main():
    httpd = HTTPServer(('localhost',8000),Serv)
    httpd.serve_forever()

if __name__ == '__main__':
    main()
