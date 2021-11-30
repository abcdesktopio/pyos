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

# -*- coding: utf-8 -*-
import logging

# abcdesktop compute module
import oc.lib
import oc.od.settings
import oc.logging


logger = logging.getLogger(__name__)

@oc.logging.with_logger()
class ODPrinterControl:

    def __init__(self, desktop, orchestrator):
        if not desktop: 
            raise ValueError('Argument desktop not set')
        self.desktop = desktop
        self.orchestrator = orchestrator
        #'-h /tmp/.cups.sock'
        self.lpadmin_host = '/tmp/.cups.sock' 
        self.lpadmincommand = '/usr/sbin/lpadmin'
        self.lpstatcommand = '/usr/bin/lpstat'
        self.lpstatscript = '/composer/lpstatinfo.sh'
        self.lpadmin_defaultoptions = {
            'printer-is-shared': 'false',
            'media': 'iso_a4_210x297mm',    # default value if nothing can be found
            'sides': 'one-sided',
            'job-sheets': 'none,none'
        }


        # this map should to ordered by language settings
        self.mapPrintMediaReadyCups = { 'A4':           'iso_a4_210x297mm', 
                                        'A5':           'iso_a5_148x210mm', 
                                        'A3':           'iso_a3_297x420mm',
                                        'letter':       'na_letter_8.5x11in',
                                        'legal':        'na_legal_8.5x14in',                                      
                                        'Excecutive' :  'na_execuvite_7.25x10.5in'
                                        }


    def add(self, name=None, uncname=None, cn=None, location=None, language=None, options={}, printMediaReady=None, username=None, password=None, domain=None):
        logger.info('')

        def val(value):
            ''' return the first entry in a list if param is list else None else params '''
            if isinstance(value, list): 
                if len(value) > 0:
                    return value[0] 
                else:
                    return None
            return value

        def arg(switch,value):
            value = val(value)
            return '-%s \'%s\'' % (switch, value) if value else ''


        options = self.lpadmin_defaultoptions

        if type(printMediaReady) is str:
            # look for option 
            for po in self.mapPrintMediaReadyCups.keys() :
                logger.debug( 'looking for %s in %s ', po, printMediaReady )
                if printMediaReady.find( po ) != -1 :
                    logger.debug( 'setting default media printer as %s', self.mapPrintMediaReadyCups[po] )
                    options['media'] = self.mapPrintMediaReadyCups[po]
                    break

        optionargs = ''
        # convert optionargs dict to command line options
        for k,v in options.items():
            option = ' -o %s=\'%s\'' % (k,v)
            optionargs = optionargs + option
            
        logger.debug( 'optionargs %s', optionargs)
        models = oc.od.settings.printercupsdriverLanguageDict
        model = models.get(val(language), models.get('default', 'drv:///sample.drv/generic.ppd'))

        # smb://username:password@domain/hostname/printer_name
        # 'uNCName': ['\\\\SRV.MYDOMAIN.LOCAL\\PRINTER']
        uri = None

        uncname=val(uncname)
        uncname = uncname.replace('\\', '/')    
        if uncname:            
            creds = ''
            if all([username, password, domain]):
                creds = username + ':' + password + '@' + domain
            elif all([username, password]):
                creds = username + ':' + password            
            uri = 'smb://' + creds + uncname
        else:
            raise ValueError('Invalid printer uri')

        self.lpadmin(
            arg('p', name or '" "'),
            arg('m', model),            
            arg('v', uri),
            arg('D', cn),
            arg('L', location),
            optionargs,
            '-E')

    def remove(self, printerName):
        return self.lpadmin('-x ', printerName or '" "')

    def list(self):
        printernames = []
        try :
            stdout = self.lpstat('-a').split(b'\n')
            for line in stdout:
                logger.debug(line)
                try:
                    printername = line.split(b' ')[0].decode('utf-8')
                    if printername and len(printername) > 0:
                        logger.debug('printername = %s', printername)
                        printernames.append(printername)
                except Exception:
                    logger.warning('Invalid printer entry parsing string: %s', line)
        except Exception:
            logger.error('Failed to exec command %s', self.lpadmincommand )
                    
        return printernames


    def describe(self, printerName):
        '''
        printer PRINTERNAME is idle.  enabled since lun. 04 juin 2018 16:25:35 CEST
        Rendering completed
        Form mounted:
        Content types: any
        Printer types: unknown
        Description: Xerox WorkCentre 3615 PCL6
        Alerts: none
        Location: XXXXXXXXXXXXXXXXXXX
        Connection: direct
        Interface: /etc/cups/ppd/PRINTERNAME.ppd
        On fault: no alert
        After fault: continue
        Users allowed:
                (all)
        Forms allowed:
                (none)
        Banner required
        Charset sets:
                (none)
        Default pitch:
        Default page size:
        Default port settings:
        '''
        infos = {}
        for line in self.lpstat('-l', '-p', printerName).split(b'\n\t'):
            logger.debug(line)
            try:
                nv = line.split(b': ', 2)
                if len(nv) == 2: 
                    key = nv[0].decode('utf-8')
                    value = nv[1].decode('utf-8')                    
                    infos[key] = value
            except Exception:
                logger.warning('Invalid printer entry parsing string: %s', line)

        return infos

    def lpstat( self, *args):
        return self.exec( self.lpstatcommand, *args )

    def lpadmin( self, *args):
        return self.exec( self.lpadmincommand, *args )

    def exec(self, command, *args):
        ''' exec a command inside the docker container '''
        command = ' '.join([command, *[a for a in args if a]])
        logger.debug(command)

        result = self.orchestrator.execininstance( self.desktop, command )

        if type(result) is dict:
            if result.get('ExitCode') == 0:
                stdout = result.get('stdout')
                if type(result.get('stdout')) is str:
                    return stdout.encode("ascii","ignore")
                else:
                    return stdout
            else:
                errmsg = 'Command failed with error code %s: %s' % (str(result.get('exit_code')), command)        
        else:
            errmsg = 'Command failed with error code %s' % command
        logger.error(errmsg)
        raise RuntimeError(errmsg)    