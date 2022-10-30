import os
import socket
import sys
from datetime import datetime


PERSONAL_ID = '166FB8'
PERSONAL_SECRET = 'ec3d3b986eec9b7ad74e06213350ebd3'


def read_config() -> tuple:
    if len(sys.argv) < 2:
        sys.exit(1)

    if not os.path.exists(sys.argv[1]):
        sys.exit(1)

    server_port_given = False
    send_path_given = False
    properties = {}
    with open(sys.argv[1], "r") as fobj:
        for property in fobj:
            property = property.rstrip('\n')
            property_ls = property.split("=")

            if property_ls[0] ==  "server_port":
                server_port_given = True
                try:
                    property_ls[1] = int(property_ls[1])
                except ValueError:
                    sys.exit(2)
                if property_ls[1] <= 1024:
                    sys.exit(2)

            elif property_ls[0] == "send_path":
                send_path_given = True
                property_ls[1] = property_ls[1].strip('/')
                if not os.path.exists(property_ls[1]):
                    sys.exit(2)

            properties.update({property_ls[0]: property_ls[1]})
        
    if not server_port_given or not send_path_given:
        sys.exit(2)

    return (properties.get("server_port"), properties.get("send_path"))


def setup_client_connection(server_port: int) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(10)

    try:
        s.connect(("127.0.0.1", server_port))
    except ConnectionRefusedError:
        print("C: Cannot establish connection")
        sys.exit(3)
    except TimeoutError:
        print("C: Cannot establish connection")
        sys.exit(3)

    return s


def write_msg_from_server(msg: str) -> None:
    msg_ls = msg.split("\r\n")
    msg_ls.pop(-1)
    for line in msg_ls:
        sys.stdout.write(f"S: {line}\r\n")
        sys.stdout.flush()


def main():
    config_info = read_config()
    server_port = config_info[0]
    send_path = config_info[1]

    client_sock = setup_client_connection(server_port)

    quit = False
    while not quit:
        try:
            msg_from_server = client_sock.recv(1024).decode()
        except ConnectionResetError:
            sys.stdout.write("C: Connection lost\r\n")
            sys.stdout.flush()
            sys.exit(3)
        write_msg_from_server(msg_from_server)
        msg_to_server = input("C: ").rstrip('\n') + "\r\n"
        try:
            client_sock.send(msg_to_server.encode())
        except BrokenPipeError:
            sys.stdout.write("C: Connection lost\r\n")
            sys.stdout.flush()
            sys.exit(3)


if __name__ == '__main__':
    main()