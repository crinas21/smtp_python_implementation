import os
import socket
import sys
from datetime import datetime


def read_config() -> tuple:
    if len(sys.argv) < 2:
        sys.exit(1)

    if not os.path.exists(sys.argv[1]):
        sys.exit(1)

    server_port_given = False
    spy_path_given = False
    properties = {}
    with open(sys.argv[1], "r") as fobj:
        for property in fobj:
            property = property.rstrip('\n')
            property_ls = property.split("=")

            if property_ls[0] == "server_port":
                server_port_given = True
                try:
                    property_ls[1] = int(property_ls[1])
                except ValueError:
                    sys.exit(2)
                if property_ls[1] <= 1024:
                    sys.exit(2)

            if property_ls[0] == "spy_path":
                inbox_path_given = True

            if property_ls[0] == "client_port":
                try:
                    property_ls[1] = int(property_ls[1])
                except ValueError:
                    sys.exit(2)
                if property_ls[1] <= 1024:
                    sys.exit(2)

            properties.update({property_ls[0]: property_ls[1]})
        
    if not server_port_given or not inbox_path_given or \
            properties.get("server_port") == properties.get("client_port"):
        sys.exit(2)

    return (properties.get("server_port"), properties.get("client_port"), properties.get("spy_path"))


def setup_connection_as_client(server_port: int) -> socket.socket:
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


def setup_connection_as_server(client_port: int) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", client_port))
    except OSError:
        sys.exit(2)
    s.listen(1)
    return s


def main():
    config_info = read_config()
    server_port = config_info[0]
    client_port = config_info[1]
    spy_path = config_info[2]

    client_sock = setup_connection_as_client(server_port)
    server_sock = setup_connection_as_server(client_port)

    while True:
        break


if __name__ == '__main__':
    main()