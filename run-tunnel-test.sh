#!/usr/bin/env bash
# Run DNS tunnel server, client, and a quick round-trip test.
# Uses: echo server 18080, DNS 55353, client 11080 (no root needed).

set -e
cd "$(dirname "$0")"

ECHO_PORT=18080
DNS_PORT=55353
CLIENT_PORT=11080
DOMAIN=t.local

# Build once
cargo build -q 2>/dev/null || cargo build

# Start TCP echo server (destination)
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $ECHO_PORT))
s.listen(5)
print('Echo server on 127.0.0.1:$ECHO_PORT')
while True:
    c, a = s.accept()
    d = c.recv(4096)
    if not d: break
    print('Echo got:', d.decode(errors='replace'))
    c.sendall(d)
    c.close()
" &
ECHO_PID=$!

# Start DNS tunnel server
cargo run -q -- server -b 127.0.0.1:$DNS_PORT -d $DOMAIN -t 127.0.0.1:$ECHO_PORT &
SERVER_PID=$!

# Start client
cargo run -q -- client -l 127.0.0.1:$CLIENT_PORT -d 127.0.0.1 -m $DOMAIN --dns-port $DNS_PORT &
CLIENT_PID=$!

cleanup() {
  kill $ECHO_PID $SERVER_PID $CLIENT_PID 2>/dev/null
  exit 0
}
trap cleanup EXIT INT TERM

sleep 4

# Test: send through tunnel, expect echo back (response comes via poll; allow time for round-trip)
echo "Sending 'hello tunnel' to 127.0.0.1:$CLIENT_PORT ..."
RECV=$(python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(25)
s.connect(('127.0.0.1', $CLIENT_PORT))
s.sendall(b'hello tunnel')
out = s.recv(4096)
s.close()
print(out.decode(errors='replace'))
")
echo "Received: $RECV"
if [ "$RECV" = "hello tunnel" ]; then
  echo "OK: tunnel round-trip works."
else
  echo "FAIL: expected 'hello tunnel', got '$RECV'"
  exit 1
fi
