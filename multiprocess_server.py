import os
import socket
import sys
import signal
from datetime import datetime
from dataclasses import dataclass
import hmac
import base64


@dataclass(frozen=False)
class Email:
    sender: str
    recipients: list[str]
    data_lines: list[str]


PERSONAL_ID = '166FB8'
PERSONAL_SECRET = 'ec3d3b986eec9b7ad74e06213350ebd3'

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
                property_ls[1] = os.path.expanduser(property_ls[1])
                if not os.path.exists(property_ls[1]):
                    sys.exit(2)
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


def server_respond(client_sock: socket.socket, prefix: str, response: str) -> None:
    response_ls = response.split("\r\n")
    for r in response_ls:
        sys.stdout.write(f"{prefix}S: {r}\r\n")
        sys.stdout.flush()
    response += "\r\n"
    client_sock.send(response.encode('ascii'))


def inbox_mail(email: Email, inbox_path: str, authorised: bool) -> None:
    email_txt = f"From: <{email.sender}>\nTo: "

    for rcpt in email.recipients:
        email_txt += f"<{rcpt}>,"
    email_txt = email_txt.rstrip(",") + "\n"

    for data in email.data_lines:
        email_txt += data + "\n"
    email_txt = email_txt

    if email.data_lines[0].startswith("Date: "):
        date = email.data_lines[0][6:]
        try:
            date_format = datetime.strptime(date, '%a, %d %b %Y %H:%M:%S %z')
            timestamp = str(datetime.timestamp(date_format)).split(".")[0]
            filename = timestamp + ".txt"
        except ValueError:
            filename = "unknown.txt"
    else:
        filename = "unknown.txt"

    if authorised:
        filename = "auth." + filename

    filename = inbox_path + "/" + filename
    fobj = open(filename, "w")
    fobj.write(email_txt)
    fobj.close()


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
    

def process_ehlo(client_sock: socket.socket, prefix: str, parameters: str) -> int:
    if not parameters.endswith("\r\n"):
        server_respond(client_sock, prefix, CODE501)
        return 1
    
    parameters = parameters.lstrip().rstrip("\r\n")
    if not valid_ip(parameters):
        server_respond(client_sock, prefix, CODE501)
        return 1

    server_respond(client_sock, prefix, "250 127.0.0.1\r\n250 AUTH CRAM-MD5")
    return 3


def process_mail(client_sock: socket.socket, prefix: str, parameters: str, email: Email) -> int:
    if not (parameters.startswith(" FROM:<") and parameters.endswith(">\r\n")):
        server_respond(client_sock, prefix, CODE501)
        return 3

    if not valid_address(parameters[7:-3]):
        server_respond(client_sock, prefix, CODE501)
        return 3

    server_respond(client_sock, prefix, "250 Requested mail action okay completed")
    email.sender = parameters[7:-3]
    return 9


def process_rcpt(client_sock: socket.socket, prefix: str, parameters: str, email: Email) -> int:
    if not (parameters.startswith(" TO:<") and parameters.endswith(">\r\n")):
        server_respond(client_sock, prefix, CODE501)
        return 9
    
    if not valid_address(parameters[5:-3]):
        server_respond(client_sock, prefix, CODE501)
        return 9

    server_respond(client_sock, prefix, "250 Requested mail action okay completed")
    email.recipients.append(parameters[5:-3])
    return 11


def process_data(client_sock: socket.socket, prefix: str, parameters: str, email: Email) -> int:
    if parameters != "\r\n":
        server_respond(client_sock, prefix, CODE501)
        return 11
    else:
        server_respond(client_sock, prefix, "354 Start mail input end <CRLF>.<CRLF>")
        msg_from_client = client_sock.recv(1024).decode('ascii').rstrip("\r\n")
        while msg_from_client != ".":
            sys.stdout.write(f"{prefix}C: {msg_from_client}\r\n")
            sys.stdout.flush()
            server_respond(client_sock, prefix, "354 Start mail input end <CRLF>.<CRLF>")
            email.data_lines.append(msg_from_client)
            msg_from_client = client_sock.recv(1024).decode('ascii').rstrip("\r\n")

        sys.stdout.write(f"{prefix}C: {msg_from_client}\r\n")
        sys.stdout.flush()
        server_respond(client_sock, prefix, "250 Requested mail action okay completed")
        return 3


def process_rset(client_sock: socket.socket, prefix: str, parameters :str, current_state: int) -> int:
    if parameters != "\r\n":
        server_respond(client_sock, prefix, CODE501)
        return current_state
    else:
        server_respond(client_sock, prefix, "250 Requested mail action okay completed")
        return 3


def process_noop(client_sock: socket.socket, prefix: str, parameters: str) -> None:
    if parameters != "\r\n":
        server_respond(client_sock, prefix, CODE501)
    else:
        server_respond(client_sock, prefix, "250 Requested mail action okay completed")


def process_auth(client_sock: socket.socket, prefix: str, parameters: str) -> bool:
    if parameters != " CRAM-MD5\r\n":
        server_respond(client_sock, prefix, "504 Unrecognized authenticaton type")
        return False
    
    challenge = os.urandom(36)
    asc_challenge =  base64.b64encode(challenge).decode('ascii') # Decode the challenge to ascii
    encoded_challenge = base64.b64encode(asc_challenge.encode('ascii')) # Base 64 encode the ascii challenge
    sys.stdout.write(f"{prefix}S: 334 {encoded_challenge.decode('ascii')}\r\n")
    sys.stdout.flush()
    response = "334 ".encode('ascii') + encoded_challenge + "\r\n".encode('ascii') # Make plaintext ascii encoded
    client_sock.send(response) # Send message with plaintext ascii encoded and the challenge base64 encoded

    msg_from_client = client_sock.recv(1024).decode('ascii') # Contains the client_answer with ID prepended
    if msg_from_client.rstrip("\r\n") == "*":
        server_respond(client_sock, prefix, CODE501)
        return False
    printed_msg = msg_from_client.rstrip('\r\n')
    sys.stdout.write(f"{prefix}C: {printed_msg}\r\n")
    sys.stdout.flush()

    try:
        decoded_msg = base64.b64decode(msg_from_client).decode('ascii')
    except base64.binascii.Error:
        server_respond(client_sock, prefix, "535 Authentication credentials invalid")
        return False

    new_digest = hmac.new(PERSONAL_SECRET.encode('ascii'), asc_challenge.encode('ascii'), digestmod='md5').hexdigest()

    msg_digest = decoded_msg.split()[1]
    msg_id = decoded_msg.split()[0]
    if new_digest != msg_digest or PERSONAL_ID != msg_id:
        server_respond(client_sock, prefix, "535 Authentication credentials invalid")
        return False
    else:
        server_respond(client_sock, prefix, "235 Authentication successful")
        return True


def process_quit(client_sock: socket.socket, server_sock: socket.socket, prefix: str, parameters: str, current_state: int) -> int:
    if parameters != "\r\n":
        server_respond(client_sock, prefix, CODE501)
        return current_state
    else:
        server_respond(client_sock, prefix, "221 Service closing transmission channel")
        client_sock.close()
        server_sock.close()
        sys.exit(0)


def main():
    def sigint_handler(sig, frame) -> None:
        try:
            client_sock.send("421 Service not available, closing transmission\r\n".encode('ascii'))
            client_sock.close()
            server_sock.close()
        except UnboundLocalError:
            pass
        except NameError:
            pass
        except OSError:
            pass
        sys.stdout.write(f"{prefix}S: SIGINT received, closing\r\n")
        sys.stdout.flush()
        sys.exit(0)
    signal.signal(signal.SIGINT, sigint_handler)

    config_info = read_config()
    server_port = config_info[0]
    inbox_path = config_info[1]

    # Check inbox_path can be written to
    if not os.access(inbox_path, os.W_OK):
        sys.exit(2)

    server_sock = setup_server_connection(server_port)
    server_state = 7
    authorised = False
    client_num = 0
    
    while True:
        if server_state == 7:
            client_sock, address = server_sock.accept()
            client_num += 1
            pid = os.fork()
            if pid != 0:
                continue
            prefix = f"[{os.getpid()}][{client_num:02d}]"
            server_respond(client_sock, prefix, "220 Service ready")
            server_state = 1

        try:
            msg_from_client = client_sock.recv(1024).decode('ascii')
        except ConnectionResetError:
                sys.stdout.write(f"{prefix}S: Connection lost\r\n")
                sys.stdout.flush()
                client_sock.close()
                server_state = 7
                continue
        command = msg_from_client[0:4]
        parameters = msg_from_client[4:]

        # Write client msg to stdout even with multi-lines
        msg_ls = msg_from_client.split("\r\n")
        msg_ls.pop(-1)
        for line in msg_ls:
            sys.stdout.write(f"{prefix}C: {line}\r\n")
            sys.stdout.flush()

        if server_state == 3:
            email = Email(None, [], [])

        if command == "EHLO":
            server_state = process_ehlo(client_sock, prefix, parameters)
            authorised = False

        elif command == "MAIL":
            if server_state == 3:
                server_state = process_mail(client_sock, prefix, parameters, email)
            else:
                server_respond(client_sock, prefix, CODE503)

        elif command == "RCPT":
            if server_state == 9 or server_state == 11:
                server_state = process_rcpt(client_sock, prefix, parameters, email)
            else:
                server_respond(client_sock, prefix, CODE503)

        elif command == "DATA":
            if server_state == 11:
                server_state = process_data(client_sock, prefix, parameters, email)
                inbox_mail(email, inbox_path, authorised)
            else:
                server_respond(client_sock, prefix, CODE503)

        elif command == "RSET":
            server_state = process_rset(client_sock, prefix, parameters, server_state)
            authorised = False

        elif command == "NOOP":
            process_noop(client_sock, prefix, parameters)

        elif command == "AUTH":
            if server_state == 3:
                authorised = process_auth(client_sock, prefix, parameters)
            else:
                server_respond(client_sock, prefix, CODE503)

        elif command == "QUIT":
            server_state = process_quit(client_sock, server_sock, prefix, parameters, server_state)
            authorised = False

        elif command == '':
            try:
                client_sock.send("test data\r\n".encode('ascii'))
            except BrokenPipeError:
                sys.stdout.write(f"{prefix}S: Connection lost\r\n")
                sys.stdout.flush()
                client_sock.close()
                server_state = 7
            except ConnectionResetError:
                sys.stdout.write(f"{prefix}S: Connection lost\r\n")
                sys.stdout.flush()
                client_sock.close()
                server_state = 7

        else:
            server_respond(client_sock, prefix, CODE500)

if __name__ == '__main__':
    main()