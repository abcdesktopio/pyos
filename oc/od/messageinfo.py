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
#

import logging
import oc.sharecache

logger = logging.getLogger(__name__)
@oc.logging.with_logger()
class ODMessageInfoManager():    
    def __init__(self, connectionstring):
        self.memcache = oc.sharecache.ODMemcachedSharecache( connectionstring )
        self.memcacheclient = self.memcache.createclient()
        
    def get(self, key):
        return self._get( key )

    def _get(self, key):
        return self.memcacheclient.get(str(key))

    def _delete(self, key):        
        try:
            return self.memcacheclient.delete(str(key))
        except Exception:
            pass

    def delete(self, key):        
        self._delete( key )
        
    def _set(self, key, value, time=60 ):
        try:
            if self.memcacheclient.set(str(key), str(value), time) != 0: 
                return True            
        except Exception as e:
            self.logger.error( str(e) )                      
        return False

    def set(self, key, value ):
        return self._set(key, value )

    def getqueue(self, key):
        return ODMessageInfo( key, self.memcacheclient )
                
    def start(self, key, message=None):
        self._delete(key)        
        if message:
            self._set(key,message)
        return self.getqueue(key)


    def push(self, key, message):
        try:
            self._set(key,message)
            return True
        except Exception:
            return False

    def pop(self, key):
        return self._get( key )        

    def flush(self, key, left=True):
        try :
            return self._delete( key )
        except Exception:
            return None

    def popflush(self, key, left=True):
        value = self._get(key)
        self._delete(key)
        return value        

    def stop(self, key):
        self._set(key,'stopinfo')        


# 
# ODMessageInfo is like a ODMessageInfoManager
# restictied to one key 
class ODMessageInfo( ODMessageInfoManager ):

    def __init__(self, key, memcacheclient ):
        self.key = str(key)
        self.memcacheclient = memcacheclient

    def get(self):
        return super().get( self.key )
        
    def delete(self):        
        return super().delete( self.key )
        
    def set(self, value ):
        return super().set( self.key, value )
        
    def push(self, value):
        return super().push( self.key, value )
        
    def pop(self):
        return super().pop( self.key )
        
    def flush(self):
        return super().flush( self.key )
        
    def popflush(self,left=True):
        return super().popflush( self.key, left )
        
    def stop(self):
        return super().stop( self.key )        

    def __str__(self):
        return str(self.key)