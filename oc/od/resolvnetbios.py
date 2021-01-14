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
import subprocess

logger = logging.getLogger(__name__)

@oc.logging.with_logger()
class ODResolvNetbios(object):

    def __init__(self):
        # use only one shared cache 
        # no overlap support for NETBIOS NAME or conflict
        self.nmblookupCacheDict = {} # Static cache dict for nmblookup table

    def resolvenbname(self, cifsRessource, wins_servers=[]):
        resolvedcifsRessource = cifsRessource
        try:
            ar = resolvedcifsRessource.split('/')
            nasipaddr = self.nmblookup(ar[2], wins_servers )
            if nasipaddr is not None:
                resolvedcifsRessource = '//' + nasipaddr + '/' + ar[3]
            else:
                self.logger.info( str(ar[2]) + ' is not resolved by nmblookup, hop the entry exists in DNS')
        except Exception as e:
            self.logger.error('failed: %s', e)

        return resolvedcifsRessource



    def nmblookup(self, name, wins_servers):
        myip = None
        if name is None:
            self.logger.error('invalid parameters ')
            return None
        
        self.logger.info('try to find ip address for ' + str(name))
        try:
            for s in wins_servers:
                myip = self._nmblookup(s, name)
                if myip is not None:
                   return myip
        except Exception as e:
            self.logger.error('failed: %s', e)

        return myip

    def _nmblookup(self, winsserver, name, timeout=60):
        self.logger.debug('name = ' + str(name)) 
        myip = None
        ipcached = self.nmblookupCacheDict.get(name)
        if ipcached is not None:
            self.logger.info('Found cached data ' + str(name) + ' -> ' + str(ipcached))
            return ipcached

        try:
            nmblookup_command = '/usr/bin/nmblookup'

            if not name :
                self.logger.debug(nmblookup_command + ' invalid parameters ')
                return None

            command = [nmblookup_command]
            if winsserver:
                command.append( '-U')
                command.append( winsserver )
            command.append( '-R') # set recursion desired in package
            command.append( name )

            self.logger.debug( 'nmblookup command %s', command )

            procntlm = subprocess.Popen(command, stdout=subprocess.PIPE)

            # Wait up to a certain number of seconds for the process to end.
            returndict = procntlm.waitOrTerminate(timeout)

            #  "returnCode" matches return of application, or None per
            #  #terminateToKillSeconds doc above.
            if isinstance(returndict, dict):
                returnCode = returndict.get('returnCode', None)
                if returnCode is not None:
                    self.logger.info(str(nmblookup_command) + ' returnCode = ' + str(returnCode))
                    if returnCode == 0:
                        try:
                            while True:
                                # self.logger.info( 'ocad:_nmblookup readline'
                                # )
                                data = procntlm.stdout.readline()   # Alternatively proc.stdout.read(1024)
                                if len(data) == 0:
                                    break
                                data = data.decode('utf-8')
                                myline = data.split(' ')
                                if isinstance(myline, list) and len(myline) == 2:
                                    ipline = myline[0]
                                    ipar = ipline.split('.')
                                    if isinstance(ipar, list) and len(ipar) == 4:
                                        myip = ipline
                                        break

                        except Exception as e:
                            self.logger.error('failed: %s', e)
                else:
                    self.logger.info(nmblookup_command + ' failed')
            else:
                self.logger.info(nmblookup_command)
        except Exception as e:
            self.logger.error('failed: %s', e)

        # cache the resolved name into the ip dict 
        if myip is not None:
            self.nmblookupCacheDict[name] = myip

        return myip