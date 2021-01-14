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
import dns

logger = logging.getLogger(__name__)

@oc.logging.with_logger()
class ODResolvDNS(object):
    
    # return None if failed or not found
    # return a list of name if successful
    @staticmethod
    def _dns_resolver( fqdn_name, tcp=False, query_type='A'):
        resolv_list = None
        # TODO user SITE QUERY
        # This section code could be changed with site LDAP query
        try:
            # Query
            answers_IPv4 = dns.resolver.query(fqdn_name, query_type, tcp=tcp, raise_on_no_answer=True)
            resolv_list = []
            for result in answers_IPv4:
                name = result.target.to_text()
                resolv_list.append(name)         
        except dns.resolver.NoAnswer:
            logger.info("No SRV record for %s", fqdn_name)
        except dns.resolver.NXDOMAIN:
            logger.info("The name %s does not exist",  fqdn_name)
        except Exception as e:
            logger.error('failed: %s', e)
        return resolv_list

    @staticmethod
    def resolv( fqdn_name, query_type='A' ):
        # try to resolv using udp
        resolv_list =  ODResolvDNS._dns_resolver(fqdn_name, tcp=False, query_type=query_type ) 
        if resolv_list is None:
            # fallback use tcp 
            resolv_list = ODResolvDNS._dns_resolver(fqdn_name, tcp=True, query_type=query_type)
        return resolv_list