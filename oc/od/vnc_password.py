#!/usr/bin/env python3
#
# Software Name : abcdesktop.io
# Version: 0.2
# SPDX-FileCopyrightText: Copyright (c) 2020-2021 Orange
# SPDX-License-Identifier: GPL-2.0-only
#
# This software is distributed under the GNU General Public License v2.0 only
# see the "license.txt" file for more details.
#
# Author: abcdesktop.io team
# Software description: cloud native desktop service
#

import oc.logging
import oc.od.settings
import oc.auth.namedlib
import oc.lib

from Crypto.Util.strxor import strxor
import base64

class ODVncPassword(object):

    def __init__(self, initvncpassword=None) -> None:
        super().__init__()
        self._passlength = 10
        self._key = oc.od.settings.desktopvnccypherkey
        self._vncpassword = initvncpassword

    def make( self ):
        self._vncpassword = oc.lib.randomStringwithDigitsAndSymbols( self._passlength )
        return self._vncpassword




    # func to restore padding
    @staticmethod
    def repad(data):
     return data + "=" * (-len(data)%4)

    def encrypt( self ):
        """[encrypt]
            only obscuring
            encrypt is not to encrypt, use simple xor to obscur data
        Returns:
            [str]: [description]
        """
        if self._vncpassword is None:
            self.make()
        bvncpassword = str.encode(self._vncpassword)
        xorkey = self._key[ 0 : len(self._vncpassword) ]
        xorkey = str.encode( xorkey )
        xorcipher = strxor( bvncpassword, xorkey )
        ciphertextb64 = base64.b64encode( xorcipher )
        strencrypt = ciphertextb64.decode("utf-8")
        strencrypt = strencrypt.rstrip("=")
        return strencrypt

    def decrypt( self, ciphertext ):
        ciphertextb64 = self.repad( ciphertext )
        ciphertextb64 = str.encode( ciphertextb64 )
        ciphertext =  base64.b64decode( ciphertextb64 )
        xorkey = self._key[ 0 : len(ciphertext) ]
        xorkey = str.encode( xorkey )
        clearbytesdata = strxor( ciphertext, xorkey )
        self._vncpassword = clearbytesdata.decode("utf-8")
        return self._vncpassword

    def getplain( self ):
        if self._vncpassword is None:
            self.make()
        return self._vncpassword