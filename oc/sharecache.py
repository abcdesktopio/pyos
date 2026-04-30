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

from pymemcache.client.base import Client, PooledClient
from pymemcache import serde
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
        self.socket_timeout = 2 # 2 seconds  
        self.connectionstring = connectionstring
        self._client = PooledClient(
            connectionstring,
            max_pool_size=8,
            connect_timeout=self.socket_timeout,
            default_noreply=False
        )
        # serde=serde.pickle_serde

    def createclient(self):
        return self._client   # reuse pool

    def get(self, key:str):        
        try:     
            value = self.createclient().get(key) 
            # self.logger.debug(f"get({key})->{value}")           
            return value
        except Exception as e:
            self.logger.error(f"{self.connectionstring} failed, key:({key}) {e}")
            return None

    def add(self, key:str, value:str, expire:int=0):
        try:
            add = self.createclient().add( key, value, expire=expire)
            return add
        except Exception as e:
            self.logger.error(f"{self.connectionstring} failed, {key} {e}")
        return False
    
    def append(self, key:str, value:str )-> bool:
        try:
            if self.createclient().append(key, value) != 0: 
                # self.logger.debug(f"set({key})->{value}") 
                return True
            self.logger.error(f"{self.connectionstring} failed, {key} {value} return failed")
        except Exception as e:
            self.logger.error(f"{self.connectionstring} failed, {key} {e}")
        return False

    def set(self, key:str, value:str, expire:int=0 )-> bool:
        try:
            if self.createclient().set(key, value, expire=expire) != 0: 
                # self.logger.debug(f"set({key})->{value}") 
                return True
            self.logger.error(f"{self.connectionstring} failed, {key} {value} return failed")
        except Exception as e:
            self.logger.error(f"{self.connectionstring} failed, {key} {e}")
        return False

    def delete(self, key:str)-> bool:
        try:
            if self.createclient().delete(key) != 0: 
                return True
            self.logger.error(f"{self.connectionstring} failed {key} return failed")
        except Exception as e:
            self.logger.error(f"{self.connectionstring} failed, {key} {e}")
        return False

    def gets(self, key:str )->tuple[any, any]:
        """Gets the value for the key from memcached.
        Args:
            key (str): The key to get the value for.
            time (int, optional): Not used in this implementation. Defaults to 0.
        Returns:
            str: The value for the key, or None if not found.
        """
        value = None
        try:
            value = self.createclient().gets(key)
            # self.logger.debug(f"gets({key})->{value}")
        except Exception as e:
            self.logger.error(f"{self.connectionstring} failed, key:({key}) {e}")
        return value

    def cas(self, key:str, value:str, cas, expire:int=0 )->bool:
        # returns 
        # - None if the key didn’t exist, 
        # - False if it existed but had a different cas value
        # - True if it existed and was changed.
        cas_status = None
        try:
            cas_status = self.createclient().cas(key, value, cas, expire=expire)
        except Exception as e:
            self.logger.error(f"{self.connectionstring} failed, key:({key}) {e}")
        return cas_status
