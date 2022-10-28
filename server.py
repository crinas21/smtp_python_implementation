import os
import socket
import sys
from datetime import datetime


PERSONAL_ID = '166FB8'
PERSONAL_SECRET = 'ec3d3b986eec9b7ad74e06213350ebd3'

CODE220 = "220 Service ready"
CODE235 = "235 Authentication successful"
CODE354 = "354 Start mail input end <CRLF>.<CRLF>"
CODE500 = "500 Syntax error command unrecognized"
CODE501 = "501 Syntax error in parameters or arguments"
CODE503 = "503 Bad sequence of commands"
CODE504 = "504 Unrecognized authenticaion type"
CODE535 = "535 Authentication credentials invalid"


def read_config() -> tuple:
    if len(sys.argv) < 2:
        sys.exit(1)

    if not os.path.exists(sys.argv[1]):
        sys.exit(1)

    server_port_given = False
    inbox_path_given = False
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

            if property_ls[0] == "inbox_path":
                inbox_path_given = True
                if not os.path.exists(property_ls[1].strip('/')):
                    sys.exit(2)

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

    return (properties.get("server_port"), properties.get("inbox_path"))


def setup_server_connection(server_port: int) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", server_port))
    except OSError:
        sys.exit(2)
    s.listen(1)
    return s


def server_respond(client_sock: socket.socket, response: str) -> None:
    sys.stdout.write(f"S: {response}\r\n")
    sys.stdout.flush()
    response += "\r\n"
    client_sock.send(response.encode())
    

def process_ehlo(client_sock: socket.socket, parameters: list) -> int:
    if len(parameters) != 1 or parameters[0] != "127.0.0.1":
        server_respond(client_sock, CODE501)
        return 1
    else:
        ip = parameters[0]
        sys.stdout.write(f"S: 250 {ip}\nS: 250 AUTH CRAM-MD5\r\n")
        sys.stdout.flush()
        msg = f"250 {ip}\r\n250 AUTH CRAM-MD5\r\n"
        client_sock.send(msg.encode())
        return 3


def process_mail(client_sock: socket.socket, parameters: list) -> int:
    if len(parameters) > 1 or not (parameters[0].startswith("FROM:<") 
                                    and parameters[0].endswith(">")):
        server_respond(client_sock, CODE501)
        return 3
    else:
        server_respond(client_sock, "250 Requested mail action okay completed")
        return 9


def process_rcpt(client_sock: socket.socket, parameters: list) -> int:
    if len(parameters) > 1 or not (parameters[0].startswith("TO:<") 
                                    and parameters[0].endswith(">")):
        server_respond(client_sock, CODE501)
        return 9
    else:
        server_respond(client_sock, "250 Requested mail action okay completed")
        return 11


def process_data(client_sock: socket.socket, parameters: list) -> int:
    if len(parameters) != 0:
        server_respond(client_sock, CODE501)
        return 11
    else:
        server_respond(client_sock, "354 Start mail input end <CRLF>.<CRLF>")
        msg_from_client = client_sock.recv(1024).decode().rstrip("\r\n")
        while msg_from_client != ".":
            sys.stdout.write(f"C: {msg_from_client}\r\n")
            sys.stdout.flush()
            server_respond(client_sock, "354 Start mail input end <CRLF>.<CRLF>")
            msg_from_client = client_sock.recv(1024).decode().rstrip("\r\n")

        sys.stdout.write(f"C: {msg_from_client}\r\n")
        sys.stdout.flush()
        server_respond(client_sock, "250 Requested mail action okay completed")
        return 3


def process_rset(client_sock: socket.socket, parameters :list, current_state: int) -> int:
    if len(parameters) != 0:
        server_respond(client_sock, CODE501)
        return current_state
    else:
        server_respond(client_sock, "250 Requested mail action okay completed")
        return 3


def process_noop(client_sock: socket.socket, parameters: list) -> None:
    if len(parameters) != 0:
        server_respond(client_sock, CODE501)
    else:
        server_respond(client_sock, "250 Requested mail action okay completed")


def process_quit(client_sock: socket.socket, parameters: list, current_state: int) -> int:
    if len(parameters) != 0:
        server_respond(client_sock, CODE501)
        return current_state
    else:
        server_respond(client_sock, "221 Service closing transmission channel")
        client_sock.close()
        return 7


def main():
    config_info = read_config()
    server_port = config_info[0]
    inbox_path = config_info[1]

    server_sock = setup_server_connection(server_port)
    client_sock, address = server_sock.accept()
    server_respond(client_sock, CODE220)
    server_state = 1
    
    while server_state != 7:
        msg_from_client = client_sock.recv(1024).decode().rstrip("\r\n")
            
        command = msg_from_client.split()[0]
        parameters = msg_from_client.split()[1:]
        sys.stdout.write(f"C: {msg_from_client}\r\n")
        sys.stdout.flush()

        if command == "EHLO":
            server_state = process_ehlo(client_sock, parameters)

        elif command == "MAIL":
            if server_state == 3:
                server_state = process_mail(client_sock, parameters)
            else:
                server_respond(client_sock, CODE503)

        elif command == "RCPT":
            if server_state == 9 or server_state == 11:
                server_state = process_rcpt(client_sock, parameters)
            else:
                server_respond(client_sock, CODE503)

        elif command == "DATA":
            if server_state == 11:
                server_state = process_data(client_sock, parameters)
            else:
                server_respond(client_sock, CODE503)

        elif command == "RSET":
            server_state = process_rset(client_sock, parameters, server_state)

        elif command == "NOOP":
            process_noop(client_sock, parameters)

        elif command == "QUIT":
            server_state = process_quit(client_sock, parameters, server_state)

        else:
            server_respond(client_sock, CODE500)


if __name__ == '__main__':
    main()