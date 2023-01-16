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

from oc.od.services import services
import oc.od.orchestrator

class ODAccounting:
    def __init__(self):
        #
        # set accounting value to zero by default
        self.accounting = {
            'api':  { 
                'bad_parameters': 0, 
                'env_container_app':0 , 
                'stop_container_app':0 , 
                'log_container_app':0, 
                'list_container_app':0  
            },
            'login': { 
                'success': 0, 
                'failed': 0, 
                'anonymous':0 
            },
            'desktop': { 
                'new': 0, 
                'resumed': 0, 
                'current':0, 
                'createfailed':0, 
                'remove': 0 
            },
            'applist': { 
                'installed': 0, 
                'cached': 0, 
                'build':0 
            },
            'container': { 
                'current': 0, 
                'reused': 0, 
                'error':0, 
                'accessdenied':0
            }            
        }

    def get(self, keyname):
        return self.accounting.get(keyname, None)

    def account(self, keyname, value=1):
        try:
            self.accounting[keyname] += value
        except KeyError:
            self.accounting[keyname] = value

    def unaccount(self, keyname, value=1):
        self.account( keyname, -1)

    def accountex(self, keycat, keyname, value=1):
        try:
            self.accounting[keycat][keyname] += value
        except KeyError:
            self.accounting[keycat][keyname] = value

    def setaccount(self, keyname, value):
        self.accounting[keyname] = value

    def setaccountex(self, keycat, keyname, value):
        self.accounting[keycat][keyname] = value

    def todict(self):
        response = {}

        # update not updated value
        orchestrator = oc.od.orchestrator.ODOrchestratorBase.selectOrchestrator()
        self.setaccountex('desktop', 'current', orchestrator.countdesktop() )
        self.setaccountex('applist', 'installed', services.apps.countApps() )
        self.setaccountex('applist', 'cached', services.apps.getCached_image_counter() )
        self.setaccountex('applist', 'build', services.apps.getBuild_image_counter() )

        # dump data
        # for k, v in self.accounting.items():
        #     if isinstance(v, dict):
        #         for ka in v:
        #            n = oc.auth.namedlib.normalize_containername(str(ka)) if k in ['container', 'image'] else str(ka)
        #            response['counter_'+ str(k) +'_' + n] = str( v[ka] )
        #    else:
        #                
        response.update(self.accounting)

        return response