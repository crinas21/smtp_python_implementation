import os
import socket
import sys
from datetime import datetime
import hmac
import base64


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

            if property_ls[0] == "send_path":
                send_path_given = True

            if property_ls[0] == "client_port":
                try:
                    property_ls[1] = int(property_ls[1])
                except ValueError:
                    sys.exit(2)
                if property_ls[1] <= 1024:
                    sys.exit(2)

            properties.update({property_ls[0]: property_ls[1]})
        
    if not server_port_given or not send_path_given or \
            properties.get("server_port") == properties.get("client_port"):
        sys.exit(2)

    return (properties.get("server_port"), properties.get("send_path"))


def get_emails_to_send(send_path: str) -> tuple:
    # Recursively get the paths of all files contained in send_path
    file_list = []
    for root, _, filenames in os.walk(send_path):
        for filename in filenames:
            if not os.path.isfile(filename):
                file_list.append(os.path.join(root, filename))

    # Split each file's path
    for i in range(len(file_list)):
        file_list[i] = file_list[i].split('/')

    # Sort the file list alphabetically by basename
    file_list = sorted(file_list, key=lambda x:x[-1])

    # Join the paths again
    for i in range(len(file_list)):
        file_list[i] = '/'.join(file_list[i])

    return tuple(file_list)


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


def receive_msg_from_server(client_sock: socket.socket) -> str:
    try:
        msg = client_sock.recv(1024).decode('ascii')
    except ConnectionResetError:
        sys.stdout.write("C: Connection lost\r\n")
        sys.stdout.flush()
        sys.exit(3)
    msg_ls = msg.split("\r\n")
    msg_ls.pop(-1)
    for line in msg_ls:
        sys.stdout.write(f"S: {line}\r\n")
        sys.stdout.flush()
    return msg


def print_then_send_to_server(client_sock: socket.socket, msg: str) -> None:
    sys.stdout.write(f"C: {msg}\r\n")
    sys.stdout.flush()
    msg += "\r\n"
    try:
        client_sock.send(msg.encode('ascii'))
    except BrokenPipeError:
        sys.stdout.write("C: Connection lost\r\n")
        sys.stdout.flush()
        sys.exit(3)


def authenticate(client_sock: socket.socket) -> None:
    print_then_send_to_server(client_sock, "AUTH CRAM-MD5")
    server_msg = receive_msg_from_server(client_sock)
    challenge = server_msg.split()[1].rstrip("\r\n")
    decoded_challenge = base64.b64decode(challenge)
    digest = hmac.new(PERSONAL_SECRET.encode('ascii'), 
                        decoded_challenge, digestmod='md5').hexdigest()
    digest = PERSONAL_ID + " " + digest + "\r\n"
    client_answer = base64.b64encode(digest.encode('ascii'))
    sys.stdout.write(f"C: {client_answer.decode('ascii')}\r\n")
    sys.stdout.flush()
    client_sock.send(client_answer)
    #print_then_send_to_server(client_sock, client_answer.decode('ascii')) # Decode because it is later encoded
    receive_msg_from_server(client_sock)


def send_sender(client_sock: socket.socket, sender: str) -> None:
    sender = sender.split()[1].rstrip('\n')
    msg = f"MAIL FROM:{sender}"
    print_then_send_to_server(client_sock, msg)
    receive_msg_from_server(client_sock)


def send_recipients(client_sock: socket.socket, recipients: str) -> None:
    recipients = recipients.split()[1].rstrip('\n').split(",")
    for recipient in recipients:
        msg = f"RCPT TO:{recipient}"
        print_then_send_to_server(client_sock, msg)
        receive_msg_from_server(client_sock)


def send_data(client_sock: socket.socket, data: list) -> None:
    print_then_send_to_server(client_sock, "DATA")
    receive_msg_from_server(client_sock)
    for i in range(len(data)):
        data[i] = data[i].rstrip('\n')
    for section in data:
        print_then_send_to_server(client_sock, section)
        receive_msg_from_server(client_sock)
    print_then_send_to_server(client_sock, ".")
    receive_msg_from_server(client_sock)


def main():
    config_info = read_config()
    server_port = config_info[0]
    send_path = config_info[1]

    emails_to_send = get_emails_to_send(send_path)

    for email in emails_to_send:
        client_sock = setup_client_connection(server_port)
        receive_msg_from_server(client_sock)
        print_then_send_to_server(client_sock, "EHLO 127.0.0.1")
        receive_msg_from_server(client_sock)

        try:
            fobj = open(email, "r")
            contents = fobj.readlines()
            fobj.close()
        except Exception:
            sys.stdout.write(f"C: {email}: Bad formation")
            continue
        
        if "auth" in os.path.abspath(email).lower():
            authenticate(client_sock)

        send_sender(client_sock, contents[0])
        send_recipients(client_sock, contents[1])
        send_data(client_sock, contents[2:])

        print_then_send_to_server(client_sock, "QUIT")
        receive_msg_from_server(client_sock)

        client_sock.close()


if __name__ == '__main__':
    main()