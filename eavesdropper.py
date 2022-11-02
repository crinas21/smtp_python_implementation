import os
import socket
import sys
from datetime import datetime
import server as sv
import client as cl


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
                property_ls[1] = os.path.expanduser(property_ls[1])
                if not os.path.exists(property_ls[1]):
                    sys.exit(2)
                spy_path_given = True

            if property_ls[0] == "client_port":
                try:
                    property_ls[1] = int(property_ls[1])
                except ValueError:
                    sys.exit(2)
                if property_ls[1] <= 1024:
                    sys.exit(2)

            properties.update({property_ls[0]: property_ls[1]})
        
    if not server_port_given or not spy_path_given or \
            properties.get("server_port") == properties.get("client_port"):
        sys.exit(2)

    return (properties.get("server_port"), properties.get("client_port"), properties.get("spy_path"))


def print_server_msg(msg: str) -> None:
    msg_ls = msg.split("\r\n")
    msg_ls.pop(-1)
    for line in msg_ls:
        sys.stdout.write(f"S: {line}\r\n")
        sys.stdout.flush()
    for line in msg_ls:
        sys.stdout.write(f"AC: {line}\r\n")
        sys.stdout.flush()


def print_client_msg(msg: str) -> None:
    sys.stdout.write(f"C: {msg}")
    sys.stdout.flush()
    sys.stdout.write(f"AS: {msg}")
    sys.stdout.flush()


def main():
    config_info = read_config()
    server_port = config_info[0]
    client_port = config_info[1]
    spy_path = config_info[2]

    server_sock = sv.setup_server_connection(client_port) # Acting as server
    new_client_connection = True

    while True:
        if new_client_connection:
            client_sock = cl.setup_client_connection(server_port) # Acting as client
            real_cl_sock, address = server_sock.accept()
            new_client_connection = False

        server_msg = client_sock.recv(1024) # Receive msg from real server, pretending to be client
        print_server_msg(server_msg.decode('ascii'))
        real_cl_sock.send(server_msg) # Send msg to real client, pretending to be server
        if server_msg.decode('ascii').split()[0] == "221":
            client_sock.close()
            new_client_connection = True
            continue

        client_msg = real_cl_sock.recv(1024) # Receive msg from real client, pretending to be server
        print_client_msg(client_msg.decode('ascii'))
        client_sock.send(client_msg) # Send msg to real server, pretending to be client


if __name__ == '__main__':
    main()