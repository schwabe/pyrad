#!/usr/bin/env python3
import sys

import pyrad.packet

from pyrad.client import Client
from pyrad.dictionary import Dictionary


def main(coa_type, nas_identifier):
    # create coa client
    client = Client(server='127.0.0.1',
                    secret=b'Kah3choteereethiejeimaeziecumi',
                    dict=Dictionary('dictionary'))

    # set coa timeout
    client.timeout = 30

    # create coa request packet
    attributes = {
        'Acct-Session-Id': '1337',
        'NAS-Identifier': nas_identifier,
    }

    if coa_type == 'coa':
        # create coa request
        request = client.CreateCoAPacket(**attributes)
    elif coa_type == 'dis':
        # create disconnect request
        request = client.CreateCoAPacket(
            code=pyrad.packet.DisconnectRequest,
            **attributes)
    else:
        sys.exit(1)

    # send request
    result = client.SendPacket(request)
    print(result)
    print(result.code)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('usage: coa.py {coa|dis} daemon-1234')
        sys.exit(1)

    main(sys.argv[1], sys.argv[2])
