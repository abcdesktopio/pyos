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
import oc.lib
from Crypto.Util.strxor import strxor
import base64

class ODVncPassword():
    """[ODVncPassword]
        ODVncPassword class to obscur vnc password 
        this is not a encrypt password
        the goal is only obscur vnc password 
    """
    def __init__(self, key, initvncpassword=None, passwordlen=10) -> None:
        """[__init__]
            init ODVncPassword class
        Args:
            key ([str]): [cypher key]
            initvncpassword ([str], optional): [default vnc password value]. Defaults to None.
            passwordlen (int, optional): [len of the vnc password if it does not exist]. Defaults to 10.
        """
        super().__init__()
        self._passlength = passwordlen
        self._key = key
        self._vncpassword = initvncpassword

    def make( self ):
        """[make]
            build a vnc password plain text using random value for length 
            self._passlength = 10 bydefault
        Returns:
            [type]: [description]
        """
        self._vncpassword = oc.lib.randomStringwithDigitsAndSymbols( self._passlength )
        return self._vncpassword

    @staticmethod
    def repad(data):
        """[repad]
            restore padding if need 
        Args:
            data ([str]): [string without base64 pad]

        Returns:
            [str]: [string with base64 pad if need ]
        """
        return data + "=" * (-len(data)%4)

    def encrypt( self ):
        """[encrypt]
            only obscuring
            encrypt is not to encrypt, 
            use simple xor to obscur data
        Returns:
            [str]: [xor encrypted password base64 formated]
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
        """[decrypt]
            only obscuring
            decrypt is not to encrypt, 
            decrypt decoded xor string
  
        Args:
            ciphertext ([str]): [cypher xor base64 formated ]

        Returns:
            [str]: [plain text data]
        """
        ciphertextb64 = self.repad( ciphertext )
        ciphertextb64 = str.encode( ciphertextb64 )
        ciphertext =  base64.b64decode( ciphertextb64 )
        xorkey = self._key[ 0 : len(ciphertext) ]
        xorkey = str.encode( xorkey )
        clearbytesdata = strxor( ciphertext, xorkey )
        self._vncpassword = clearbytesdata.decode("utf-8")
        return self._vncpassword

    def getplain( self ):
        """[getplain]
            get vnc password plain text
        Returns:
            [str]: [clear vnc password plain text]
        """
        if self._vncpassword is None:
            self.make()
        return self._vncpassword