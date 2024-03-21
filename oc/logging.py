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

import sys
import inspect
import logging
import logging.config
import pymongo
import graypy # graylog lib
import cherrypy
from cherrypy.lib.reprconf import Config
from cherrypy._cplogging import LogManager
from cherrypy import _json as json

from oc.cherrypy import getclientipaddr

logger = logging.getLogger(__name__)

# Return the name of a function in the call stack
def func_name(frame_num=0,append_module=True):
    try:
        frame = sys._getframe(frame_num + 1)
        name = frame.f_code.co_name
        if append_module:
            try:
                return inspect.getmodule(frame).__name__ + '.' + name
            except Exception:
                pass
        return name
    except Exception:
        return ''

# Class decorator that add a 'logger' field refering a logging.Logger named as the owner class
# Usage:
#
# @with_logger()
# class MyC(object):
#   pass
#
# MyC().logger.info('Ok')
def with_logger(name=None,prop_name=None):
  def decorate(cls):
        setattr(cls, prop_name or 'logger', logging.getLogger(name or cls.__module__ + '.' + cls.__name__))
        return cls
  return decorate


def load_config(path, is_cp_file=False): 
    """ 
        load the config file from default configuration file 'od.config' if is_cp_file is True 
        load the config file PATH if is_cp_file is False """
    cfg_logging = None

    if is_cp_file is True:
        logger.info(f"Reading cherrypy configuration section 'global/logging': path = {path}")
        config = Config(path)
        if isinstance( config.get('global'), dict ):
            cfg_logging = config.get('global').get('logging')
        else:
            cfg_logging = config.get('logging')
    else:
        logger.info(f"Reading json file: path = {path}")
        with open(path, encoding='UTF-8') as f: 
            cfg_logging = json.decode(f.read())

    logger.debug(f"logging configuration : {cfg_logging}")
    return cfg_logging


def init_logging(config_or_path, is_cp_file=True):   
    ''' init logging, load configuration file logging section '''
    logger.info("Initializing logging subsystem")
    
    cfg = config_or_path if isinstance(config_or_path, dict) else load_config(config_or_path, is_cp_file)

    logger.info("Applying configuration")
    logging.config.dictConfig(cfg)


def configure(config_or_path='config/logging.json', is_cp_file=False):    
    try:        
        cherrypy.config.update({'log.screen': False, 'log.access_file': '',  'log.error_file': ''})
        init_logging(config_or_path, is_cp_file)  
    except Exception:
        logger.critical("Failed to configure logging: config_or_path = %s", repr(config_or_path), exc_info=True)        
        cherrypy.config.update({'log.screen': True })


class OdContextFilter(logging.Filter):
    ''' Log Filter that add to the current log record a 'userid' field containing the user id (extracted from the http request) '''
    def filter(self, record):        
        ''' Log Filter that add to the current log record a userid field    '''
        ''' containing the user id (extracted from the http request)        '''
        record.userid = 'internal' # by default this is not a http request
        try:  
            if cherrypy.request.app : # if the log message come from an a http request
                record.userid = 'anonymous' # by default user is anonymous 
                if  hasattr(cherrypy.request, 'odauthcache')       and \
                    hasattr(cherrypy.request.odauthcache, 'user')  and  \
                    hasattr(cherrypy.request.odauthcache.user, 'userid'):                    
                    record.userid = cherrypy.request.odauthcache.user.userid
            else:
                record.userid = 'internal'  # not an http request             
        except Exception:
            pass
         
        record.ipaddr = 'localhost'
        try:
            if cherrypy.request.app : # if the log message come from an a http request
                record.ipaddr = getclientipaddr()
        except Exception as e :
            logger.error("Error when trying to get client IP Address")
            logger.error( e )

        return True


class MongoFormatter(logging.Formatter):
    def __init__(self, mapping={}):
        super().__init__()
        self.mapping = {}
        part = None
        for k, v in mapping.items():
            part = None
            if callable(v):
                part = v
            elif isinstance(v,dict):
                fld = v.get('field', None)
                fmt = v.get('format', None)
                if fld and fmt:
                    # ex: { "timestamp": "field":"created", "format":"{:0.0f}" }
                    part = lambda record,fld=fld,fmt=fmt: fmt.format(getattr(record, fld, None))
                elif fld:                    
                    # ex: { "timestamp": "created" }
                    part = lambda record,fld=fld: getattr(record, fld, None)
                elif fmt:
                    # ex: { "funcstamp": { "format": "{funcName}+{created:0.0f}" } }
                    part = lambda record,fmt=fmt: fmt.format(**record.__dict__)
            else:
                part = v

            if part is not None: 
                self.mapping[k] = part

    def format(self, record):
        doc = {}
        for k, v in self.mapping.items(): 
            try:
                doc[k] = v(record) if callable(v) else v
            except Exception:
                doc[k] = None
        return doc


class MongoHandler(logging.Handler):
    def __init__(self, address, port, database, collection, login=None, password=None, mapping={
            'created': { 'field':'created' }, 
            'message': { 'field':'message' }, 
            'level'  : { 'field':'levelname' }
        }):
        super().__init__()
        self.address = address
        self.port = port
        self.database = database
        self.collection = collection
        self.client = None
        self.setFormatter(MongoFormatter(mapping))

    def close(self):
        super().close()
        if self.client: 
            self.client.close()
            self.client = None

    def ensure_client(self):
        if not self.client: 
            self.client = pymongo.MongoClient(self.address, self.port)

    def emit(self, record):
        try:
            self.ensure_client()
            self.client[self.database][self.collection].insert_one(self.format(record))
        except Exception:            
            logger.debug('',exc_info=True)


def __init__():
    # Remove hardcoded timestamp from CherryPy messages
    LogManager.time = lambda self: ""
    handler = logging.StreamHandler()    
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)-7s] %(name)s.%(funcName)s: %(message)s"))
    logger.addHandler(handler)
    logger.propagate = False
    logger.setLevel(logging.INFO)
    
__init__()
