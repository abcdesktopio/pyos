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
import time
import random
import logging
import oc.logging
import oc.sharecache

logger = logging.getLogger(__name__)

@oc.logging.with_logger()
class ODReplicatInstance:
    
    def __init__(self, keyname:str, endpoint:str, memcache_connection_string:str ):
        self.keyname = keyname
        self.endpoint = endpoint
        self.memcache = oc.sharecache.ODMemcachedSharecache( memcache_connection_string )
  
   
    def register_endpoint(self)-> bool:
        nCount = 0
        addstatus = self.memcache.add(self.keyname, self.endpoint )
        while addstatus is False and nCount < 10:
            # Key already exists, we can assume a running replicat is already registered
            serialized_endpoints, cas = self.memcache.gets( self.keyname )

            # Check if the endpoint is already registered
            if self.endpoint in serialized_endpoints.split('+'):
                self.logger.debug(f"Endpoint {self.endpoint} already registered for key {self.keyname}={serialized_endpoints}")
                return True
            
            # We need to add the endpoint to the existing value
            if len(serialized_endpoints)> 0:
                serialized_endpoints += '+' + self.endpoint
            else:
                serialized_endpoints = self.endpoint
            addstatus = self.memcache.cas(self.keyname, serialized_endpoints, cas )
            if addstatus is False:
                time.sleep( random.randint(0, nCount) )  # Wait for a second before retrying
                nCount += 1
        if addstatus is False:
            self.logger.error(f"Failed to register endpoint {self.endpoint} for key {self.keyname}")
        return addstatus
        
    def get_endpoints(self)-> list:
        # Get the value for the key from memcached
        value = self.memcache.get(self.keyname)
        if value is None:
            # self.logger.debug(f"Failed to get value for key {self.keyname}")
            return None
        values = value.split('+')
        if len(values) == 0:
            # self.logger.debug(f"Failed to get value for key {self.keyname}, no values found")
            return None
        self.logger.debug(f"get_endpoints({self.keyname})->{values}")
        return values
    
    def unregister_endpoint(self)-> bool:
        addstatus = False
        serialized_endpoints, cas= self.memcache.gets( self.keyname )
        if isinstance( serialized_endpoints, str ):
            endpoints = serialized_endpoints.split('+')
            new_endpoints = []
            for value in endpoints:
                if value != self.endpoint:
                    new_endpoints.append( value )
            
            # check if we need to delete the key
            if len(new_endpoints) == 0:
                # We have removed the last endpoint, we can delete the key
                addstatus = self.memcache.delete(self.keyname)
                if addstatus is False:
                    self.logger.error(f"Failed to delete key {self.keyname}")
                return addstatus
            
            # check if we need to update the key
            if len(new_endpoints) < len(endpoints):
                # We have removed an endpoint, we can update the key
                new_value = '+'.join(new_endpoints)
                addstatus = self.memcache.cas(self.keyname, new_value, cas )
                if addstatus is False:
                    self.logger.error(f"Failed to update key {self.keyname} with value {new_value}")
        return addstatus
