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
import urllib
import json

logger = logging.getLogger(__name__)

@oc.logging.with_logger()
class ODInternalDNS():    

    def __init__(self, server, secret, domain='desktop.local' ):
        
        self.domain = domain
        self.server = server
        self.secret = secret

        if not isinstance(server,str) :
            raise ValueError('Invalid internal dns server value')

        if not isinstance(secret,str) :
            raise ValueError('Invalid internal dns secret value')            

        # http://myhost.mydomain.tld:8080/update?secret=changeme&domain=foo&addr=1.2.3.4
        self.url = f"http://{server}:8080/update"


    def get_targetfqdn( self, hostname ):
        return f"{hostname}.{self.domain}"

    def update_dns(self, hostname, ipaddr ):

        bReturn = False    

        if type(hostname) is not str :
            raise ValueError('Invalid internal dns server value')

        # url = self.url + '?secret=' + self.secret + '&domain=' + hostname + '&addr=' + ipaddr

        values = {  'secret': self.secret,
                    'domain': hostname,
                    'addr': ipaddr
        }       
        try:
            data = urllib.parse.urlencode(values)
            url = self.url + '?' + data
            self.logger.info( f"update url: {url}" )
            response = urllib.request.urlopen(url)
        except IOError as e:
            self.logger.error( f"IOError url {self.url} failed {e}" )         
        except Exception as e:
            self.logger.error( f"url {self.url} failed {e}" )            
        else:
            # everything is fine
            try:
                if response.code == 200:
                    encoding = response.info().get_content_charset('utf-8')
                    content = response.read()
                    response.close()
                    # {"Success":true,"Message":"Updated A record for e96f94bb-84ed-4a64-8080-03399e6da748 to IP address 10.244.0.89","Domain":"e96f94bb-84ed-4a64-8080-03399e6da748","Domains":["e96f94bb-84ed-4a64-8080-03399e6da748"],"Address":"10.244.0.89","AddrType":"A"}
                    jsondns = json.loads(content.decode(encoding))
                    self.logger.info( f"dns response {content.decode(encoding)}" )
                    
                    dnssuccess = jsondns.get('Success', False)
                    dnsresponseaddr = jsondns.get('Address', '')
                    dnsresponsetype = jsondns.get('AddrType', '')
                    if  dnssuccess and \
                        dnsresponseaddr == ipaddr and \
                        dnsresponsetype == 'A':
                       bReturn = True
            except Exception as e:
                self.logger.error( f"dns response error {e}" )
       
        self.logger.info( f"bReturn {bReturn}" )
        
        if bReturn : 
            return self.get_targetfqdn( hostname )
        else:
            return None        
