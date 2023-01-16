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
import uuid
from Crypto.PublicKey import RSA as rsa

import oc.od.services

logger = logging.getLogger(__name__)

class ODDesktopKeyManager(object):

    def __init__( self, config ):
        self.privateprefix = 'priv.'
        self.expire_in = config.get('exp', 180)
        self.algorithms=['RS256']
        jwt_desktop_privatekeyfile    = config.get('jwtdesktopprivatekeyfile')
        jwt_desktop_publickeyfile     = config.get('jwtdesktoppublickeyfile')
        
        f = open(jwt_desktop_privatekeyfile, 'r')        
        self.jwt_privatekey = f.read()
        f.close()

        f = open(jwt_desktop_publickeyfile, 'r')        
        self.jwt_publickey = f.read()
        f.close()
       

    def generatekey(self, length=2048):
        key = rsa.generate(length)
        return key

    def storekey(self, key ):
        privatekey = key.exportKey('PEM').decode()
        publickey  = key.publickey().exportKey('PEM').decode()

        struuid = str( uuid.uuid4() )
        data = {    'name': struuid, 
                    'publickey': publickey,
                    'exp' : self.expire_in}

        keyname = self.privateprefix + struuid
        encoded_jwt = jwt.encode( data, self.jwt_privatekey, algorithm=self.algorithms[0])
        oc.od.services.services.sharecache.set( keyname, privatekey, self.expire_in )
        return encoded_jwt
        
    
    def decode(self, keyname, enc_data ):
        data = None
        try:
            keyname = self.privateprefix + keyname
            priv = oc.od.services.services.sharecache.get(keyname)
            privatekey = rsa.importKey(priv)
            data = privatekey.decrypt(enc_data)
        except Exception as e:
            self.logger.error( e )
        return data


    def encode( self, length=2048 ):
        key = self.generatekey( length )
        jwt = self.storekey( key )
        return jwt
   