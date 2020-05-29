#!/usr/bin/env python3
import socket
import sys

import pyrad.packet

from pyrad.client import Client
from pyrad.dictionary import Dictionary


def main():
    srv = Client(server='localhost',
                 authport=18121,
                 secret=b'test',
                 dict=Dictionary('dictionary'))

    req = srv.CreateAuthPacket(
        code=pyrad.packet.StatusServer,
        FreeRADIUS_Statistics_Type= 'All',
    )
    req.add_message_authenticator()

    try:
        print('Sending FreeRADIUS status request')
        reply = srv.SendPacket(req)
    except pyrad.client.Timeout:
        print('RADIUS server does not reply')
        sys.exit(1)
    except socket.error as error:
        print('Network error: ' + error[1])
        sys.exit(1)

    print('Attributes returned by server:')
    for key, value in reply.items():
        print(f'{key}: {value}')


if __name__ == '__main__':
    main()
