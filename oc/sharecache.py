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

    def add(self, key, value, time=0 ):
        try:
            if self.createclient().add(str(key), str(value), time=time) != 0: 
                self.logger.debug(f"set({key})->{value}") 
                return True
            self.logger.error(f"{self.connectionstring} failed, {key} {value} return failed")
        except Exception as e:
            self.logger.error(f"{self.connectionstring} failed, {key} {e}")
        return False
    
    def append(self, key, value, time=0 ):
        try:
            if self.createclient().append(str(key), str(value), time=time) != 0: 
                self.logger.debug(f"set({key})->{value}") 
                return True
            self.logger.error(f"{self.connectionstring} failed, {key} {value} return failed")
        except Exception as e:
            self.logger.error(f"{self.connectionstring} failed, {key} {e}")
        return False

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
            if self.createclient().delete(str(key)) != 0: 
                return True
            self.logger.error(f"{self.connectionstring} failed {key} return failed")
        except Exception as e:
            self.logger.error(f"{self.connectionstring} failed, {key} {e}")

        return False

    def gets(self, key:str, time=0 )->tuple[any, any]:
        """Gets the value for the key from memcached.
        Args:
            key (str): The key to get the value for.
            time (int, optional): Not used in this implementation. Defaults to 0.
        Returns:
            str: The value for the key, or None if not found.
        """
        try:
            value = self.createclient().gets(key)
            # self.logger.debug(f"gets({key})->{value}")
            return value
        except Exception as e:
            self.logger.error(f"{self.connectionstring} failed, key:({key}) {e}")
            return None, None

    def cas(self, key, value )->bool:
        # returns 
        # - None if the key didn’t exist, 
        # - False if it existed but had a different cas value
        # - True if it existed and was changed.
        try:
            cas_status = self.createclient().cas(key, value)
            return cas_status
        except Exception as e:
            self.logger.error(f"{self.connectionstring} failed, key:({key}) {e}")
            return None

    def createclient(self):
        return memcache.Client(servers=[self.connectionstring], socket_timeout=self.socket_timeout)
    
