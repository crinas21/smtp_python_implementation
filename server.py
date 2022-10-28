import os
import socket
import sys
from datetime import datetime


PERSONAL_ID = '166FB8'
PERSONAL_SECRET = 'ec3d3b986eec9b7ad74e06213350ebd3'

CODE220 = "220 Service ready"
CODE235 = "235 Authentication successful"
CODE354 = "354 Start mail input end <CRLF>.<CRLF>"
CODE500 = "500, Syntax error command unrecognized"
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

            if property_ls[0] ==  "server_port":
                server_port_given = True
                try:
                    property_ls[1] = int(property_ls[1])
                except ValueError:
                    sys.exit(2)
                if property_ls[1] <= 1024:
                    sys.exit(2)

            elif property_ls[0] == "inbox_path":
                inbox_path_given = True
                if not os.path.exists(property_ls[1].strip('/')):
                    sys.exit(2)

            properties.update({property_ls[0]: property_ls[1]})
        
    if not server_port_given or not inbox_path_given:
        sys.exit(2)

    return (properties.get("server_port"), properties.get("inbox_path"))


def setup_server_connection(server_port: int) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", server_port))
    s.listen(1)
    return s


def server_respond(client_sock: socket.socket, response: str) -> None:
    sys.stdout.write(f"S: {response}\n")
    sys.stdout.flush()
    response = response + "\r\n"
    client_sock.send(response.encode())
    

def process_ehlo(client_sock: socket.socket, parameters: list) -> int:
    if parameters[0] == "127.0.0.1\r\n":
        sys.stdout.write(f"S: 250 127.0.0.1\nS: 250 AUTH CRAM-MD5\n")
        sys.stdout.flush()
        client_sock.send(b"250 127.0.0.1\r\n250 AUTH CRAM-MD5\r\n")
        return 3
    else:
        server_respond(client_sock, CODE501)
        return 1


def process_mail(client_sock: socket.socket, parameters: list) -> int:
    if len(parameters) > 1:
        server_respond(client_sock, CODE501)
    server_respond(client_sock, "250 Requested mail action okay completed")


def main():
    server_port = read_config()[0]
    inbox_path = read_config()[1]

    server_sock = setup_server_connection(server_port)
    client_sock, address = server_sock.accept()
    server_respond(client_sock, CODE220)
    server_state = 1
    
    sigint = False
    while not sigint:
        msg_from_client = client_sock.recv(1024).decode()
        if len(msg_from_client) != 0:
            command = msg_from_client.split(' ')[0]
            parameters = msg_from_client.split(' ')[1:]
            sys.stdout.write(f"C: {msg_from_client}")
            sys.stdout.flush()

            if command == "EHLO":
                server_state = process_ehlo(client_sock, parameters)

            elif command == "MAIL":
                if server_state == 3:
                    server_state = process_mail(client_sock, parameters)
                else:
                    server_respond(client_sock, CODE503)

            elif command == "RCPT":
                pass

            elif command == "DATA":
                pass

            else:
                server_respond(client_sock, CODE500)


if __name__ == '__main__':
    main()