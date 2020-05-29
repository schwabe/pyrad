#!/usr/bin/env python3
import socket
import sys

import pyrad.packet

from pyrad.client import Client
from pyrad.dictionary import Dictionary


def main():
    srv = Client(server='127.0.0.1',
                 secret=b'Kah3choteereethiejeimaeziecumi',
                 dict=Dictionary('dictionary'))

    req = srv.CreateAuthPacket(
        code=pyrad.packet.AccessRequest,
        **{
        'User-Name': 'wichert',
        'NAS-IP-Address': '192.168.1.10',
        'NAS-Port': 0,
        'Service-Type': 'Login-User',
        'NAS-Identifier': 'trillian',
        'Called-Station-Id': '00-04-5F-00-0F-D1',
        'Calling-Station-Id': '00-01-24-80-B3-9C',
        'Framed-IP-Address': '10.0.0.100',
    })

    try:
        print('Sending authentication request')
        reply = srv.SendPacket(req)
    except pyrad.client.Timeout:
        print('RADIUS server does not reply')
        sys.exit(1)
    except socket.error as error:
        print('Network error: ' + error[1])
        sys.exit(1)

    if reply.code == pyrad.packet.AccessAccept:
        print('Access accepted')
    else:
        print('Access denied')

    print('Attributes returned by server:')
    for key, value in reply.items():
        print(f'{key} {value}')


if __name__ == '__main__':
    main()
