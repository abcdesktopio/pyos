#!/usr/bin/env python3.8
#
# Software Name : abcdesktop.io
# Version: 0.1
# SPDX-FileCopyrightText: Copyright (c) 2020-2022 Orange
# SPDX-License-Identifier: GPL-2.0-only
#
# This software is distributed under the GNU General Public License v2.0 only
# see the "license.txt" file for more details.
#
# Author: abcdesktop.io team
# Software description: cloud native desktop service
#
# graylog tester is a simple graylog client to send message to graylog  
#
# ./graylog-tester.py
# usage: graylog-tester [-h] [--hostname HOSTNAME] [--port PORT] [--protocol {UDP,TCP,HTTP}] [--message MESSAGE] [--loglevel LOGLEVEL]
#
# send a message using python graypy.GELF API
#
# optional arguments:
#   -h, --help            show this help message and exit
#   --hostname HOSTNAME   graylog hostname, the default value is 'localhost'
#   --port PORT           graylog port number, the default value is 12201
#   --protocol {UDP,TCP,HTTP}
#                        protocol can be 'UDP' or 'TCP' or 'HTTP', the default value is 'UDP'
#   --message MESSAGE     message to send to the graylog server, the default value is 'Hello graylog world'
#   --loglevel LOGLEVEL   loglevel can be DEBUG or WARNING or INFO or ERROR or CRITICAL or FATAL, the default value is DEBUG
#
# 

import argparse
import logging
import graypy
import sys


def sendmessage( hostname:str, port:int, message:str='Hello graylog world', protocol:str='UDP', loglevel:str='DEBUG' ):

    my_logger = logging.getLogger('test_logger')

    level_dict = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'CRITICAL': logging.CRITICAL,
        'ERROR': logging.ERROR,
        'FATAL': logging.FATAL,
        'WARNING' : logging.WARNING
    }
    level = level_dict.get( loglevel )
    if not isinstance( level, int):
        print( f"level {loglevel} is unsupported" )
        exit(-1)

    lambda_handlers = { 
        'UDP' : graypy.GELFUDPHandler, 
        'TCP' : graypy.GELFTCPHandler,
        'HTTP' : graypy.GELFHTTPHandler }
    
    lambda_handler = lambda_handlers.get( protocol )
    if not callable(lambda_handler):
        print( f"procotol {protocol} is unsupported" )
        exit(-1)

    handler = lambda_handler( hostname, port)
    my_logger.addHandler(handler)
    my_logger._log(level, message, None )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='graylog-tester', description='send a message using python graypy.GELF API')
    # hostname:str, port:int, message:str='Hello Graylog.', protocol:str='UDP', loglevel
    parser.add_argument("--hostname", type=str, help="graylog hostname, the default value is 'localhost'",  default='localhost')
    parser.add_argument("--port",     type=int, help="graylog port number, the default value is 12201",  default=12201)
    parser.add_argument("--protocol", type=str, help="protocol can be 'UDP' or 'TCP' or 'HTTP', the default value is 'UDP'", choices=['UDP', 'TCP', 'HTTP'], default='UDP')
    parser.add_argument("--message",  type=str, help="message to send to the graylog server, the default value is 'Hello graylog world'", default="Hello graylog world")
    # choices=['UDP', 'TCP', 'HTTP'], 'UDP', 'TCP', 'HTTP'
    # choices=['DEBUG', 'INFO', 'CRITICAL', 'ERROR', 'FATAL']
    parser.add_argument("--loglevel",    type=str, help="loglevel can be DEBUG or WARNING or INFO or ERROR or CRITICAL or FATAL, the default value is DEBUG", default='DEBUG')
    args = parser.parse_args()
    print(f"sending message to hostname={args.hostname}, port={args.port}, message='{args.message}', protocol={args.protocol},  level={args.loglevel}")
    sendmessage( hostname=args.hostname, port=args.port, message=args.message, protocol=args.protocol, loglevel=args.loglevel  )
    print(f"done")
