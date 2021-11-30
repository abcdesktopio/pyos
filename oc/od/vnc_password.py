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
import base64
import oc.lib
from os import urandom
# from Crypto.Cipher import AES
# from hashlib import pbkdf2_hmac


class ODVncPassword():
    """[ODVncPassword]
        ODVncPassword class  
    """
    def __init__(self, key=None, defaultvncpassword=None) -> None:
        """[__init__]
            init ODVncPassword class
        Args:
            key ([str]): [cypher key]
            initvncpassword ([str], optional): [default vnc password value]. Defaults to None.
            passwordlen (int, optional): [len of the vnc password if it does not exist]. Defaults to 10.
        """
        #
        # passlength must respect len(labels) <= 63 chars for kubernetes
        # 35 is the max len
        self._passlength = 15
        self._key = key
        if key is None:
            # key length use password length
            self._key = oc.lib.randomStringwithHexa( 32 )
        self._vncpassword = defaultvncpassword


    def get_key( self ):
        return self._key

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
    def repadb32(data):
        """[repad]
            restore padding for base32 if need ( using modulo 8 )
        Args:
            data ([str]): [string without base32 pad]

        Returns:
            [str]: [string with base32 pad if need ]
        """
        return data + "=" * (-len(data)%8)


    def getcypherkey(self):
        ciphertextb32 = base64.b32encode( self._key )
        strencrypt = ciphertextb32.decode("utf-8")
        return strencrypt


    def encrypt( self ):
        """[encrypt]
            only obscuring
            
        Returns:
            [str]: [ base 32 str]
        """
        if self._vncpassword is None:
            self.make()

        # convert _vncpassword as bytes
        bvncpassword = str.encode(self._vncpassword)
        bs = AES.block_size
        salt = urandom(bs - len(b'Salted__'))
        pbk = pbkdf2_hmac('sha256', self._key, salt, 10000, 48)
        key = pbk[:32]
        iv = pbk[32:48]

        # create cipher
        cipher = AES.new(key, AES.MODE_CBC, iv)
        result = (b'Salted__' + salt)
        chunk = bvncpassword[:1024*bs]
        padding_length = (bs - len(chunk) % bs) or bs
        chunk += (padding_length * chr(padding_length)).encode()
        result += cipher.encrypt(chunk)
        b32result = base64.b32encode( result )
        return b32result

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

        """
        # restor = pad if need
        ciphertextb32 = str.encode( ciphertext )
        # decode b32
        ciphertext =  base64.b32decode( ciphertextb32 )
        iv = ciphertext[:16]
        # create cipher
        cipher = AES.new(key, AES.MODE_CBC, iv)
        result = (b'Salted__' + salt)

        cipher.decrypt( enc[16:] )
        b32result = base64.b32encode( result )
        return b32result
      
        msg = cipher.decrypt(ciphertext)
        
        self._vncpassword = msg.decode("utf-8")
        """
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