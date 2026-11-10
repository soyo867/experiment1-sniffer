"""Generate a controlled HTTP exchange on 127.0.0.1 only (no Internet access)."""
import argparse
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = b"WireScope Experiment 1A: real loopback packet capture.\n"
        self.send_response(200)
        self.send_header("Content-Type","text/plain; charset=utf-8")
        self.send_header("Content-Length",str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def generate(port=18080, count=5, interval=0.5):
    server = ThreadingHTTPServer(("127.0.0.1",port),Handler)
    worker = threading.Thread(target=server.serve_forever,daemon=True)
    worker.start()
    try:
        connection = http.client.HTTPConnection("127.0.0.1",server.server_port,timeout=5)
        for i in range(count):
            connection.request("GET",f"/experiment/1a?request={i+1}",headers={"User-Agent":"WireScope-Controlled-Test"})
            response = connection.getresponse()
            data = response.read()
            if response.status != 200 or b"real loopback" not in data:
                raise RuntimeError("Unexpected test response")
            time.sleep(interval)
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port",type=int,default=18080)
    parser.add_argument("--count",type=int,default=8)
    args = parser.parse_args()
    generate(args.port,args.count)
    print(f"Completed {args.count} HTTP requests over localhost:{args.port}")
