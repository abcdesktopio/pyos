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

import jwt
import logging
import time
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, PKCS1_OAEP
import Crypto.Hash.SHA1 
import Crypto.Hash.SHA256 
import Crypto.Hash.SHA512

logger = logging.getLogger(__name__)

class ODDesktopJWToken(object):

    def __init__( self, config ):
        
        # Please take care with HS256
        # https://auth0.com/blog/brute-forcing-hs256-is-possible-the-importance-of-using-strong-keys-to-sign-jwts/
        # prefere RS256, reduce the size of cryto
        self.privatekey = None
        self.publickey  = None        
        self._exp  = int(config.get('exp', 180))
        # read leeway
        self.leeway = int( config.get('leeway', 20) )
        self.algorithms=['RS256']  
        
        jwt_desktop_privatekeyfile    = config.get('jwtdesktopprivatekeyfile')
        payload_desktop_publickeyfile = config.get('payloaddesktoppublickeyfile')
        self.rsa_encryption_protocol  = config.get('rsaencryptionprotocol', 'PKCS1_v1_5')
        self.rsa_hash_protocol        = config.get('rsahashprotocol', 'SHA256')
        
        # read jwt_desktop_privatekeyfile
        with open(jwt_desktop_privatekeyfile, 'r') as f:
            self.jwt_privatekey = f.read()
        
        # read payload_desktop_publickeyfile
        with open(payload_desktop_publickeyfile, 'r') as f:
            self.payload_desktop_publickeyfile = f.read()

        # # uncomment to call decode method
        # jwt_desktop_publickeyfile = config.get('jwtdesktoppublickeyfile')l decode me# thod
        #
        # # read the jwt_desktop_publickeyfile
        # f = open(jwt_desktop_publickeyfile, 'r')
        # self.jwt_publickey = f.read()
        # f.close()

    def exp(self):
        return self._exp

    # decrypt does not exist
    # decrypt is used by nginx lua script
    def encrypt( self, msg):

        # import the payload_desktop_publickeyfile
        rsakey = RSA.importKey( self.payload_desktop_publickeyfile )
        
        if self.rsa_encryption_protocol == 'PKCS1_OAEP':
            # crypto.subtle.decrypt 
            hashAlgo = Crypto.Hash.SHA1 # default value 
            if self.rsa_hash_protocol == 'SHA1':
                hashAlgo = Crypto.Hash.SHA1
            if self.rsa_hash_protocol == 'SHA256':
                hashAlgo = Crypto.Hash.SHA256
            if self.rsa_hash_protocol == 'SHA512':
                hashAlgo = Crypto.Hash.SHA512
            pubobj = PKCS1_OAEP.new(key=rsakey, hashAlgo=hashAlgo )
            crypto = pubobj.encrypt(msg)
        else :
            # self.rsa_encryption_protocol == 'PKCS1_v1_5':
            pubobj = PKCS1_v1_5.new(rsakey)
            crypto = pubobj.encrypt(msg)
        return base64.b64encode( crypto )     

                
                
    def encode( self, data ):   
        # pyos encrypt the data with the public key from nginx
        # and nginx use his private key to decrypt it           
        encrypt_hash = self.encrypt(data.encode('ascii'))
        now = int( time.time() )
        expire_in = now + self._exp
        token = {   'key' : 0,
                    'nfb': now,
                    'hash': encrypt_hash.decode('ascii'),
                    'exp' : expire_in }        
        encoded_jwt = jwt.encode( token , self.jwt_privatekey, algorithm=self.algorithms[0]) 
        return encoded_jwt

    # this section code code should never be use
    # this is only for test 
    # this section code is only to test nginx reverse proxy
    # pyos encode and nginx decode
    #
    # def decode( self, payload ):
    #    data = None
    #    if payload is None:
    #       raise ValueError('invalid payload data')            
    #    data = jwt.decode(
    #        payload, 
    #        self.jwt_publickey, 
    #        leeway=self.leeway, 
    #        algorithms=self.algorithms[0],
    #        options={ 'require': ['exp', 'nbf', 'key', 'hash'] })
    #    return data
