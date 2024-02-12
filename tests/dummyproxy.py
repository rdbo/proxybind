import socket

print("[dummyproxy]")

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 6969))
except Exception as e:
    print("failed to bind socket")
    exit(1)

sock.listen(1)

while True:
    print("listening...")
    conn, addr = sock.accept()

    data = conn.recv(4 + 16 + 8) # Read only proxybind header: sockfd (sz = 4), sockaddr (sz = 16), size (sz = 8)
    print(f"received proxybind data header from client: {data}")

    family = int.from_bytes(data[4:6], "little")
    port = int.from_bytes(data[6:8])
    ipaddr = data[8:12]
    print(f"sockaddr family: {family}")
    print(f"sockaddr port: {port}")
    print(f"sockaddr ipaddr: {ipaddr}")

    ipaddr = socket.inet_ntoa(ipaddr)
    print(f"parsed ipaddr: {ipaddr}")

    msgsize = int.from_bytes(data[20:], "little")
    print(f"client message size: {msgsize}")

    msgdata = conn.recv(msgsize)
    msg = msgdata.decode()
    print(f"client message: {msg}")

    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.connect((ipaddr, port))
    except:
        print("failed to connect to server")
        exit(1)
    """
    new_msg = "bada"
    print(f"sending modified message to server: {new_msg}")

    server_sock.send(new_msg.encode())
    msg = server_sock.recv(256).decode()
    print(f"intercepted message from server: {msg}")

    new_msg = "bing"
    print(f"sending modified message to client: {new_msg}")
    conn.send(new_msg.encode())
    """

    print("sending original message to the server")
    server_sock.send(msgdata)

    print("sending original response to the client")
    conn.send(server_sock.recv(2048))

    print(f"disconnecting from server...")
    server_sock.close()

    print(f"disconnecting client...")
    conn.close()
