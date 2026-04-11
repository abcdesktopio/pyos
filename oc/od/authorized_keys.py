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

import logging
import oc.logging
import cryptography
import threading

logger = logging.getLogger(__name__)

    
@oc.logging.with_logger()
class ODAuthorizedKeys():
    def __init__( self, default_list={} ):
        assert isinstance( default_list, dict ), "default_list should be a dict"
        self.default_list = default_list
        self.keys = self.default_list.copy()
        self.lock = threading.Lock()

    def remove_key( self,  key:str )->bool :
        bReturn = False
        self.lock.acquire()
        try:
            del self.keys[key]
            bReturn = True
        except Exception as e:
            self.logger.error( e )
        finally:
            self.lock.release()
        return bReturn

    def add_key( self,  key:str, x509_cert:cryptography.x509.Certificate)->bool :
        assert isinstance( key, str ), "key should be a string"
        assert isinstance( x509_cert, cryptography.x509.Certificate ), "x509_cert should be an instance of cryptography.x509.Certificate"
        bReturn = False
        authorized_key = self.get_public_bytes( x509_cert )
        if isinstance( authorized_key, str):
            self.lock.acquire()
            try:
                self.keys[key] = authorized_key
                bReturn = True
            except Exception as e:
                self.logger.error( e )
            finally:
                self.lock.release()
        return bReturn

    def get_public_bytes( self, x509_cert:cryptography.x509.Certificate, encoding = cryptography.hazmat.primitives.serialization.Encoding.OpenSSH)->str:
        new_line_authorized_key = None
        try:
            authorized_key = x509_cert.public_key().public_bytes(encoding)
            # output is bytes, convert to string using ascii encoding, as OpenSSH format is ascii text
            new_line_authorized_key = authorized_key.decode('ascii') 
        except Exception as e:  
            self.logger.error(f"Error while converting x509 certificate to authorized key format: {e}")
        return new_line_authorized_key

    def clear_keys( self )->None:
        self.lock.acquire()
        try:
            self.keys = self.default_list.copy()
        except Exception as e:
            self.logger.error( e )
        finally:
            self.lock.release()

    def list( self, format:str='str' )->str:
        nl = None
        mylist = ''
        self.lock.acquire()
        try:
            nl = self.keys.copy()
        except Exception as e:
            self.logger.error( e )
        finally:
            self.lock.release()

        if format == 'dict':
            return nl
        
        for public_key in nl.values():
            if len(mylist) > 0:
                mylist += '\n'
            mylist += public_key

        return mylist