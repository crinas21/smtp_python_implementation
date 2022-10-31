import os
import socket
import sys
import signal
from datetime import datetime
from dataclasses import dataclass
import hmac
import base64


@dataclass(frozen=True)
class Email:
    sender: str
    recipients: tuple[str]
    subject: str
    body: str


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


def valid_ip(ip: str) -> bool:
    ip = ip.split(".")
    if len(ip) != 4:
        return False

    for digit in ip:
        try:
            num = int(digit)
        except ValueError:
            return False
        if num < 0 or num > 255:
            return False
    
    return True


def valid_address(address: str) -> bool:
    split_addr = address.split('@')
    if len(split_addr) != 2:
        return False

    dot_string = split_addr[0]
    if len(dot_string) < 1:
        return False

    # Check dot string does not begin or end with "."
    if dot_string[0] == "." or dot_string[-1] == ".":
        return False

    # Check if any sections separated by dots start with a "-"
    split_dot_string = dot_string.split(".")
    for st in split_dot_string:
        if st[0] == "-":
            return False

    # Check all characters are alphanumeric or "-" or "."
    dot_string_ls = list(dot_string)
    for char in dot_string_ls:
        if not (char.isalnum() or char == "-" or char == "."):
            return False

    domain = split_addr[1]
    if len(domain) < 3:
        return False

    if domain[0] == "[" and domain[-1] == "]": # If in square brackets, check if IPv4 address is valid
        if not valid_ip(domain[1:-1]):
            return False
    else:
        if domain[0] == "." or domain[-1] == ".":
            return False

        domain = domain.split(".")
        if len(domain) < 2:
            return False
        for d in domain:
            d_ls = list(d)
            if d_ls[0] == "-" or d_ls[-1] == "-":
                return False
            for char in d_ls:
                if not (char.isalnum() or char == "-" or char == "."):
                    return False

    return True
    

def process_ehlo(client_sock: socket.socket, parameters: str) -> int:
    if not parameters.endswith("\r\n"):
        server_respond(client_sock, CODE501)
        return 1
    
    parameters = parameters.lstrip().rstrip("\r\n")
    if not valid_ip(parameters):
        server_respond(client_sock, CODE501)
        return 1

    sys.stdout.write(f"S: 250 127.0.0.1\r\nS: 250 AUTH CRAM-MD5\r\n")
    sys.stdout.flush()
    msg = f"250 127.0.0.1\r\n250 AUTH CRAM-MD5\r\n"
    client_sock.send(msg.encode())
    return 3


def process_mail(client_sock: socket.socket, parameters: str) -> int:
    if not (parameters.startswith(" FROM:<") and parameters.endswith(">\r\n")):
        server_respond(client_sock, CODE501)
        return 3

    if not valid_address(parameters[7:-3]):
        server_respond(client_sock, CODE501)
        return 3

    server_respond(client_sock, "250 Requested mail action okay completed")
    return 9


def process_rcpt(client_sock: socket.socket, parameters: str) -> int:
    if not (parameters.startswith(" TO:<") and parameters.endswith(">\r\n")):
        server_respond(client_sock, CODE501)
        return 9
    
    if not valid_address(parameters[5:-3]):
        server_respond(client_sock, CODE501)
        return 9

    server_respond(client_sock, "250 Requested mail action okay completed")
    return 11


def process_data(client_sock: socket.socket, parameters: str) -> int:
    if parameters != "\r\n":
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


def process_rset(client_sock: socket.socket, parameters :str, current_state: int) -> int:
    if parameters != "\r\n":
        server_respond(client_sock, CODE501)
        return current_state
    else:
        server_respond(client_sock, "250 Requested mail action okay completed")
        return 3


def process_noop(client_sock: socket.socket, parameters: str) -> None:
    if parameters != "\r\n":
        server_respond(client_sock, CODE501)
    else:
        server_respond(client_sock, "250 Requested mail action okay completed")


def process_auth(client_sock: socket.socket, parameters: str):
    if parameters != " CRAM-MD5\r\n":
        server_respond(client_sock, "504 Unrecognized authenticaton type")
        return 3
    
    challenge = os.urandom(36)
    encoded_challenge = base64.b64encode(challenge)
    response = f"334 {encoded_challenge.decode()}"
    server_respond(client_sock, response)

    msg_from_client = client_sock.recv(1024).decode()
    sys.stdout.write(f"C: {msg_from_client}")
    sys.stdout.flush()
    msg_from_client = msg_from_client.rstrip("\r\n")
    decoded_msg = base64.b64decode(msg_from_client, validate=True).decode()
    new_digest = hmac.new(PERSONAL_SECRET.encode(), challenge, 'md5').hexdigest()

    if new_digest == decoded_msg.split()[1]:
        server_respond(client_sock, "235 Authentication successful")
    else:
        server_respond(client_sock, "535: Authentication credentials invalid")
    return 3


def process_quit(client_sock: socket.socket, parameters: str, current_state: int) -> int:
    if parameters != "\r\n":
        server_respond(client_sock, CODE501)
        return current_state
    else:
        server_respond(client_sock, "221 Service closing transmission channel")
        return 7


def sigint_handler(sig, frame) -> None:
    sys.stdout.write("S: SIGINT received, closing\r\n")
    sys.stdout.flush()
    sys.exit(0)


def main():
    signal.signal(signal.SIGINT, sigint_handler)

    config_info = read_config()
    server_port = config_info[0]
    inbox_path = config_info[1]

    server_sock = setup_server_connection(server_port)
    server_state = 7
    
    while True:
        if server_state == 7:
            client_sock, address = server_sock.accept()
            server_respond(client_sock, CODE220)
            server_state = 1

        msg_from_client = client_sock.recv(1024).decode()
        command = msg_from_client[0:4]
        parameters = msg_from_client[4:]
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

        elif command == "AUTH":
            if server_state == 3:
                server_state = process_auth(client_sock, parameters)
            else:
                server_respond(client_sock, CODE503)

        elif command == "QUIT":
            server_state = process_quit(client_sock, parameters, server_state)

        else:
            server_respond(client_sock, CODE500)


if __name__ == '__main__':
    main()