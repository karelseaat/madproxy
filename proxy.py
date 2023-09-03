import socket
import os
import threading
import select
import curses
import time
from datetime import datetime
from typing import List, Tuple
import base64
import pprint

# ------------------------------------------ Debug --------------------------------------------------
DEBUG_MODE = False

def debug_print(fmt):
    if DEBUG_MODE:
        print(fmt)

# ------------------------------------------ Shared Resources --------------------------------------------------
cache_lock = threading.Lock()
cache = {}

requests_lock = threading.Lock()
requests = []
REQUEST_NONE = 0
REQUEST_CACHED = 1
REQUEST_BLOCKED = 2

blocked_lock = threading.Lock()
blocked_urls = []

# ------------------------------------------ Management Console --------------------------------------------------

CONSOLE_WINDOW_ID = False
BLOCKED_WINDOW_ID = True


def app(stdscr):
    # Options
    # curses.curs_set(0)

    # Window Creation
    # console_window = curses.newwin(curses.LINES - int(curses.LINES / 3), curses.COLS, 0, 0)
    # keymap_window = curses.newwin(int(curses.LINES / 3), int(curses.COLS / 2), curses.LINES - int(curses.LINES / 3), 0)
    # blocked_window = curses.newwin(int(curses.LINES / 3), int(curses.COLS / 2), curses.LINES - int(curses.LINES / 3), int(curses.COLS / 2))
    focused_window = False # False for console, True for blocked urls
    # details_window = curses.newwin(curses.LINES, curses.COLS, 0, 0)
    details_page = False
    selected_packet = 0
    selected_url = 0

    # max_urls = int(curses.LINES / 3) - 2 # Max number of URLs that can be displayed on the screen at once
    # block_min = 0
    # block_max = len(blocked_urls) - 1 if len(blocked_urls) < max_urls else max_urls - 1

    # max_requests = curses.LINES - int(curses.LINES / 3) - 2 # Max number of packets that can be displayed on the screen at once
    # request_min = 0
    # request_max = (len(requests) - 1) if (len(requests) < max_requests) else (max_requests - 1)

    while True:

        if not details_page:
            pass

        else:
            c = stdscr.getch()
            if c == ord('q'):
                break
            elif c == 27: # Escape
                details_page = False

# ------------------------------------------ PROXY --------------------------------------------------

class HTTPRequest:
    method: str
    url: str
    version: str
    headers: dict

    port: int # 80 for http and 443 for https
    https: bool
    length: int
    connect_host: bytes # Parse URL for socket connection

    def __init__(self, raw_data):
        self.raw_data = raw_data
        self.length = len(raw_data)
        self.parse()
        # self.print()


    def parse(self):
        split_data = self.raw_data.split(b"\r\n")
        request_line = split_data[0].split(b" ")

        url = []
        self.https = False

        headers = {}
        for i in range(1, len(split_data)):
            if (split_data[i] == b""):
                break
            header = split_data[i].split(b": ")
            headers[header[0]] = header[1]

        if b"http://" in request_line[1]:
            url.append(request_line[1][7:])
        elif b":" in request_line[1]:
            self.https = True
            url = request_line[1].split(b":")
        else:
            url.append(request_line[1])

        self.method = request_line[0]
        self.url = url[0]
        self.version = request_line[2]
        self.headers = headers
        self.port = 443 if self.https else 80




        if b"Host" in self.headers:
            if b":" in self.headers[b"Host"]:
                url = self.headers[b"Host"].split(b":")
                self.connect_host = url[0]
            else:
                self.connect_host = self.headers[b"Host"]
        else:
            self.connect_host = self.url



def get_content_length(response):
        result = []
        len_index = response.find(b"Content-Length")
        if len_index != -1:
            len_index = len_index + 15
            i = len_index
            while chr(response[i]) != '\r':
                character = chr(response[i])
                if character.isdigit():
                    result.append(chr(response[i]))
                i = i + 1
            return int(''.join(result))
        return -1

def receive_http_response(sock):
    response = b""
    content_length = -1
    try:
        while True:
            if content_length != -1 and len(response) >= content_length:
                break
            chunk = sock.recv(4096)
            response = response + chunk
            if content_length == -1 and b"Content-Length" in response:
                content_length = get_content_length(response)
            if len(chunk) == 0:
                break
    except TimeoutError:
        debug_print("[-] Timeout occurred")
    sock.close()
    debug_print(f"[-] Received response of length {len(response)}")
    return response


# Relay packets when using HTTP
def relay(conn, http_request):
    # Track total transferred bytes
    total_bytes = 0

    # Handle checking cached and blocked list
    request_status = REQUEST_NONE
    with cache_lock:
        if http_request.url in cache:
            request_status = REQUEST_CACHED
    with blocked_lock:
        if http_request.url in blocked_urls:
            request_status = REQUEST_BLOCKED
    with requests_lock:
        debug_print(f"[-] Added packet to requests!")
        requests.append((datetime.now().strftime("%H:%M:%S"), http_request, request_status))
    if request_status == REQUEST_BLOCKED:
        debug_print(f"[-] Failed - URL is blocked")
        response = b"HTTP/1.1 403 Forbidden\r\n\r\n"
        conn.sendall(response)
        conn.close()
        return

    response = b""
    if request_status == REQUEST_CACHED:
        # Caching
        debug_print(f"[-] Using cached website for HTTP")
        response = cache[http_request.url]
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((http_request.connect_host, http_request.port))
        sock.sendall(http_request.raw_data)
        total_bytes = total_bytes + len(http_request.raw_data)
        response = receive_http_response(sock)
        cache[http_request.url] = response
        sock.close()
    conn.sendall(response)
    total_bytes = total_bytes + len(response)
    conn.close()
    debug_print(f"[-] Finished relaying packet...")
    return total_bytes

# Create a TCP tunnel when using HTTPS
def tunnel(client_conn, http_request):

    # Handle checking blocked list
    request_status = REQUEST_NONE
    with blocked_lock:
        if http_request.url in blocked_urls:
            request_status = REQUEST_BLOCKED
    with requests_lock:
        debug_print(f"[-] Added packet to requests!")
        requests.append((datetime.now().strftime("%H:%M:%S"), http_request, request_status))
    debug_print(f"[-] Received HTTPS Request - Creating Tunnel")
    if request_status == REQUEST_BLOCKED:
        debug_print(f"[-] Failed - URL is blocked")
        response = b"HTTP/1.1 403 Forbidden\r\n\r\n"
        client_conn.sendall(response)
        client_conn.close()
        return

    # If not blocked, continue as normal
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.connect((http_request.connect_host, http_request.port))

    response = b"HTTP/1.1 200 OK\r\n\r\n"
    client_conn.sendall(response)

    # Websocket
    conns = [client_conn, server_sock]
    while True:
        recvlist, _, error = select.select(conns, [], conns, 3)
        if error or not recvlist:
            break
        for r in recvlist:
            other = conns[1] if r is conns[0] else conns[0]
            data = r.recv(4096)
            if not data:
                break
            other.sendall(data)
    server_sock.close()
    client_conn.close()
    debug_print(f"[-] Closed HTTPS tunnel!")

def profile_relay(conn, http_request):
    start = time.perf_counter()
    total_bytes_trans = relay(conn, http_request)
    end = time.perf_counter()
    time_taken_s = (end - start)
    debug_print(f"Relayed HTTP request and response in {time_taken_s * 1000}ms - Transferred {total_bytes_trans / time_taken_s} bytes per second")

def handle_connection(data, conn):
    if data:
        debug_print(f"-------------------------------------------------------")
        debug_print(f"[-] Received connection - parsing packet")
        # Parse HTTP packet
        http_request = HTTPRequest(data)
        if http_request.https:
            tunnel(conn, http_request)
        else:
            profile_relay(conn, http_request)
        debug_print(f"-------------------------------------------------------")

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8080

def proxy():
    # Await Connection
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((PROXY_HOST, PROXY_PORT))
    sock.listen(1)
    debug_print(f"[-] Awaiting connection to proxy server on {PROXY_HOST}:{PROXY_PORT}...")

    # Receive Requests
    while True:
        conn, addr = sock.accept()
        data = conn.recv(4096)
        thread = threading.Thread(target=handle_connection, args=(data, conn, ))
        thread.start()

def main():
    # Start Proxy
    pt = threading.Thread(target=proxy)
    pt.start()

    # Start Management Console
    if not DEBUG_MODE:
        curses.wrapper(app)
        print(f"[-] Shutting down proxy...")
        os._exit(0)

if __name__ == "__main__":
    main()
