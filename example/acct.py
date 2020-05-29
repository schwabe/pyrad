#!/usr/bin/env python3
import random
import socket
import sys

import pyrad.packet

from pyrad.client import Client
from pyrad.dictionary import Dictionary


def send_accounting_packet(srv, req):
    try:
        srv.SendPacket(req)
    except pyrad.client.Timeout:
        print('RADIUS server does not reply')
        sys.exit(1)
    except socket.error as error:
        print('Network error: ' + error[1])
        sys.exit(1)


def main():
    srv = Client(server='127.0.0.1',
                 secret=b'Kah3choteereethiejeimaeziecumi',
                 dict=Dictionary('dictionary'))

    req = srv.CreateAcctPacket(**{
        'User-Name': 'wichert',
        'NAS-IP-Address': '192.168.1.10',
        'NAS-Port': 0,
        'NAS-Identifier': 'trillian',
        'Called-Station-Id': '00-04-5F-00-0F-D1',
        'Calling-Station-Id': '00-01-24-80-B3-9C',
        'Framed-IP-Address': '10.0.0.100',
    })

    print('Sending accounting start packet')
    req['Acct-Status-Type'] = 'Start'
    send_accounting_packet(srv, req)

    print('Sending accounting stop packet')
    req['Acct-Status-Type'] = 'Stop'
    req['Acct-Input-Octets'] = random.randrange(2**10, 2**30)
    req['Acct-Output-Octets'] = random.randrange(2**10, 2**30)
    req['Acct-Session-Time'] = random.randrange(120, 3600)
    req['Acct-Terminate-Cause'] = random.choice(['User-Request', 'Idle-Timeout'])
    send_accounting_packet(srv, req)


if __name__ == '__main__':
    main()
