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

import memcache
import oc.logging

class ODSharecacheBase(object):
    """ODSharecacheBase
        virtual class to set and get

    Args:
        object (_type_): _description_
    """
    def get(self, key):
        raise NotImplementedError( f"class {self.__class__.__name__} does not implement method get")

    def set(self, key, value):
        raise NotImplementedError( f"class {self.__class__.__name__} does not implement method set")


@oc.logging.with_logger()
class ODMemcachedSharecache(ODSharecacheBase):
    """ODMemcachedSharecache

    Args:
        ODSharecacheBase (_type_): ODSharecacheBase
    """
    def __init__(self, connectionstring):
        self.socket_timeout     = 2 # 2 seconds  
        self.connectionstring   = connectionstring

    def get(self, key):        
        try:     
            value = self.createclient().get(str(key))   
            self.logger.debug(f"get({key})->{value}")             
            return value
        except Exception as e:
            self.logger.error(f"{self.connectionstring} failed, key:({key}) {e}")
            return None

    def set(self, key, value, time=0 ):
        try:
            if self.createclient().set(str(key), str(value), time=time) != 0: 
                self.logger.debug(f"set({key})->{value}") 
                return True
            self.logger.error(f"{self.connectionstring} failed, {key} {value} return failed")
        except Exception as e:
            self.logger.error(f"{self.connectionstring} failed, {key} {e}")
        return False

    def delete(self, key, time=0 ):
        try:
            if self.createclient().delete(str(key), time=time) != 0: 
                return True
            self.logger.error(f"{self.connectionstring} failed {key} return failed")
        except Exception as e:
            self.logger.error(f"{self.connectionstring} failed, {key} {e}")

        return False

    def createclient(self):
        return memcache.Client(servers=[self.connectionstring], socket_timeout=self.socket_timeout)
