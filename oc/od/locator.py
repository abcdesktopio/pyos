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
from netaddr import IPNetwork, IPAddress


logger = logging.getLogger(__name__)

def resolvlocation_activeDirectory( ipAddr, locatorPrivateActiveDirectory ):
    assert type(ipAddr) is str, "ipAddr is not a str: %r" % ipAddr
    assert type(locatorPrivateActiveDirectory) is ODLocatorActiveDirectory, "locatorPrivateActiveDirectory is not an ODLocatorActiveDirectory: %r" % locatorPrivateActiveDirectory
    
    location = ODLocation( ipAddr=ipAddr, location=None)
    if type( locatorPrivateActiveDirectory ) is ODLocatorActiveDirectory : 
        try:            
            _location = locatorPrivateActiveDirectory.locate( ipAddr )                
            if _location : 
                location = _location
        except Exception as e:
            logger.error( e )
    else:
        logger.error( 'Invalid locatorPrivateActiveDirectory object' )
    return location
    

def resolvlocation( ipAddr, locatorPublicInternet, locatorPrivateActiveDirectory, **kargs ):

    assert type(ipAddr) is str, "ipAddr is not a str: %r" % id

    # set default return empty value
    location = ODLocation( ipAddr=ipAddr)  

    # Check if the ipAddr is Public 
    if ODLocatorBase.isPublic( ipAddr ) :
        # make sure params locatorPublicInternet is ODLocatorPublicInternet        
        if type(locatorPublicInternet) is ODLocatorPublicInternet : 
            try:
                _location = locatorPublicInternet.locate( ipAddr )
                if _location: 
                    location = _location                    
            except Exception as e:
                logger.error( e )
        else:
            logger.error( 'Invalid ODLocatorPublicInternet object' )

    elif ODLocatorBase.isPrivate( ipAddr ) :
        # No information can be obtain from Public Internet Geo Ip database
        # Look for in site Activedirectory
        # make sure params locatorPrivateActiveDirectory is ODLocatorActiveDirectory
        if type(locatorPrivateActiveDirectory) is ODLocatorActiveDirectory:
            location = resolvlocation_activeDirectory( ipAddr, locatorPrivateActiveDirectory )
        
    # location is not Private ipAdrr, and not a Public ipAddr
    # it could be a multicast IPAddr but this does not make sense
    # return a default empty location object not resolved
    return location.toDict()


    

class ODLocation():
    def __init__( self, site=None, subnet=None, country=None, country_code=None, ipAddr=None, location=[], 
                        timezone=None, datasource=None, resolved=False, siteObject=None):
        self._site = site
        self._location = location
        self._ipAddr = ipAddr
        self._country = country
        self._country_code = country_code
        self._timezone = timezone
        self._resolved = resolved
        self._datasource = datasource
        self._subnet = subnet
        self._siteObject = siteObject

    @property
    def site(self): 
        return self._site

    @property
    def datasource(self):
        return self._datasource

    @property
    def resolved(self):
        return self._resolved

    @property
    def location(self):
        return self._location

    @property
    def ipAddr(self):
        return self._ipAddr

    @property
    def country(self): 
        return self._country

    @property
    def country_code(self):
        return self._country_code

    @property
    def timezone(self):
        return self._timezone

    @property
    def subnet(self):
        return self._subnet

    @property
    def siteObject(self):
        return self._siteObject

    def toDict(self):
        return {    'site': self.site,
                    'subnet': self.subnet,
                    'ipAddr': self.ipAddr,                     
                    'country': self.country, 
                    'country_code': self.country_code, 
                    'location': self.location, 
                    'timezone':self.timezone,
                    'siteObject': self.siteObject,
                    'datasource': self.datasource }

class ODLocatorBase():
    def __init__(self):
        self._datasource = None

    @property
    def datasource(self): 
        return self._datasource

    @staticmethod
    def isPrivate( ipAddr):
        return IPAddress(ipAddr).is_private()

    @staticmethod
    def isPublic( ipAddr):
        myIpAddr = IPAddress(ipAddr)
        # unicast and not private
        return myIpAddr.is_unicast() and not myIpAddr.is_private()

    def locate(self, ipAddr):
        raise NotImplementedError('%s.desktop' % type(self))


class ODLocatorActiveDirectory(ODLocatorBase):

    def __init__(self, site, domain=None):
        super().__init__()
        self._datasource = 'activedirectory'
        self.site = site
        self.domain = domain

    def locate( self, ipAddr ):        
        logger.info('ipAddr=%s', ipAddr)
        mysite = None
        location = None
        
        myIP = IPAddress(ipAddr)
        for key in self.site:                
            if myIP in IPNetwork(key):
                mysite = self.site.get(key)
                break                    

        if type(mysite) is dict:
            # siteObject = mysite.get('siteObject'),
            # the location is the site name
            # site = location 
            location = ODLocation(  site = mysite.get('location'),
                                    location = mysite.get('location'),
                                    subnet = mysite.get('subnet'),                                    
                                    datasource = self.datasource,                                    
                                    ipAddr=ipAddr,
                                    resolved=True )
        else:            
            logger.warning( 'IpAddr %s not found in Active Directory site/subnet', ipAddr )

        return location
    

class ODLocatorPublicInternet( ODLocatorBase ):
    def __init__(self):
        super().__init__()
        self._datasource = 'geoip'
        try:
            import GeoIP
            self.geoIP = GeoIP.open("/usr/share/GeoIP/GeoIPCity.dat", GeoIP.GEOIP_STANDARD)
        except Exception as e:
            logger.error( 'GeoIP error in open file /usr/share/GeoIP/GeoIPCity.dat')
            logger.error( e )

    def locate( self, ipAddr ):        
        logger.debug('Looking for ipAddr location %s', ipAddr)
        location = None
        gir = self.geoIP.record_by_addr( ipAddr )            
        location = ODLocation(  country=gir.get('country_name'), 
                                country_code=gir.get('country_code'), 
                                ipAddr=ipAddr, 
                                location=[ gir.get('latitude'), gir.get('longitude') ],
                                timezone=gir.get('time_zone'),
                                datasource = self.datasource,
                                resolved=True )
        return location