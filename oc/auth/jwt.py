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

logger = logging.getLogger(__name__)
class ODJWToken( object):

    def __init__( self, config ):
        self.config = config
        # Please take care with HS256
        # https://auth0.com/blog/brute-forcing-hs256-is-possible-the-importance-of-using-strong-keys-to-sign-jwts/
        # prefere if bits length is to small
        # self.algorithms=['HS256']
        self.algorithms=['RS256'] 
        jwt_user_privatekeyfile    = config.get('jwtuserprivatekeyfile')
        jwt_user_publickeyfile     = config.get('jwtuserpublickeyfile')

        # load private key
        f = open(jwt_user_privatekeyfile, 'r')        
        self.jwt_privatekey = f.read()
        f.close()

        # load public key
        f = open(jwt_user_publickeyfile, 'r')        
        self.jwt_publickey = f.read()
        f.close()

        # read exp
        self._exp = int(config.get('exp', 180))
        # read leeway
        self.leeway = int( config.get('leeway', 20) )


    def encode( self, auth, user, roles ):
        now = int( time.time() )
        expire_in = now + self._exp
        token = { 
            'exp' : expire_in, 
            'nbf': now, # Not Before Time Claim (nbf)
            'auth': auth, 
            'user': user, 
            'roles': roles }
        # All data can be ready clearly
        encoded_jwt = jwt.encode( token , self.jwt_privatekey, algorithm=self.algorithms[0])
        return encoded_jwt

    def decode( self, payload ):
        data = None
        assert isinstance( payload, str ), 'invalid payload data'

        # There is no public or private key concept, all keys are private   
        # pyos use a the private key and the public key  
        # 
        # can     raise ExpiredSignatureError("Signature has expired")
        # jwt.exceptions.ExpiredSignatureError: Signature has expired 
        #             
        # add some leeway if JWT payload is expired, it will still validate      
        data = jwt.decode(
            payload, 
            self.jwt_publickey, 
            leeway=self.leeway, 
            algorithms=self.algorithms, 
            options={ 'require': ['exp', 'nbf', 'auth', 'user', 'roles'] } )
        
        return data