from http.server import SimpleHTTPRequestHandler, HTTPServer
import ssl

PORT = 8443

def start_https_server():
    handler = SimpleHTTPRequestHandler
    httpd = HTTPServer(('localhost', PORT), handler)
    httpd.socket = ssl.wrap_socket(
        httpd.socket,
        keyfile="key.pem",
        certfile="cert.pem",
        server_side=True
    )
    print(f"HTTPS server running at https://localhost:{PORT}")
    httpd.serve_forever()

if __name__ == "__main__":
    start_https_server()
