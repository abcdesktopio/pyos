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
        raise NotImplementedError(  'Class %s doesn\'t implement method %s' %
                                    (self.__class__.__name__, 'get'))

    def set(self, key, value):
        raise NotImplementedError(  'Class %s doesn\'t implement method %s' %
                                    (self.__class__.__name__, 'set'))


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
            self.logger.debug('memcached get(%s)->%s', key, value)             
            return value
        except Exception as e:
            self.logger.error('memcached %s failed, key:(%s) %s', self.connectionstring, key, e )
            return None

    def set(self, key, value, time=0 ):
        # self.logger.debug("setting key '%s' = %s", key, value)
        try:
            if self.createclient().set(str(key), str(value), time=time) != 0: 
                self.logger.debug('memcached set(%s)->%s', key, value) 
                return True
            self.logger.error('memcached %s failed, (%s: %s) return failed', self.connectionstring, key, value)
        except Exception as e:
            self.logger.error('memcached %s failed, (%s: %s)', self.connectionstring, key, value, e)
        return False

    def delete(self, key, time=0 ):
        # self.logger.debug("setting key '%s' = %s", key, value)
        try:
            if self.createclient().delete(str(key), time=time) != 0: 
                return True
            self.logger.error('memcached %s failed, (%s: %s) return failed', self.connectionstring, key)
        except Exception as e:
            self.logger.error('memcached %s failed, (%s: %s)', self.connectionstring, key, e)

        return False

    def createclient(self):
        return memcache.Client(servers=[self.connectionstring], socket_timeout=self.socket_timeout)
