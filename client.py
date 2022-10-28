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


def receive_msg_from_server(client_sock: socket.socket) -> int:
    msg = client_sock.recv(1024).decode()
    msg_ls = msg.split("\r\n")
    msg_ls.pop(-1)
    for line in msg_ls:
        sys.stdout.write(f"S: {line}\n")
        sys.stdout.flush()
    return int(msg.split(" ")[0])


def send_sender(client_sock: socket.socket, sender: str) -> None:
    sender = sender.split()[1].rstrip('\n')
    sys.stdout.write(f"C: MAIL FROM:{sender}\n")
    sys.stdout.flush()
    msg = f"MAIL FROM:{sender}\r\n"
    client_sock.send(msg.encode())


def main():
    config_info = read_config()
    server_port = config_info[0]
    send_path = config_info[1]

    emails_to_send = get_emails_to_send(send_path)
    print(emails_to_send)

    client_sock = setup_client_connection(server_port)
    receive_msg_from_server(client_sock)

    for email in emails_to_send:
        fobj = open(email, "r")
        contents = fobj.readlines()
        fobj.close()
        
        send_sender(client_sock, contents[0])
        receive_msg_from_server(client_sock)


        # msg_to_server = input("C: ").rstrip('\n') + "\r\n"
        # client_sock.send(msg_to_server.encode())


if __name__ == '__main__':
    main()