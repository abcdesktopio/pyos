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
import geoip2.database
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
    

def resolvlocation( ipAddr, locatorPublicInternet, locatorPrivateActiveDirectory ):

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


    
@oc.logging.with_logger()
class ODLocation():
    def __init__( self, site=None, subnet=None, country=None, country_code=None, ipAddr=None, location=[], 
                        timezone=None, datasource=None, resolved=False, siteObject=None, asn=None, asorganisation=None):
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
        self._asn = asn
        self._asorganisation = asorganisation

    @property
    def asn(self):
        return self._asn
    
    @property
    def asorganisation(self):
        return self._asorganisation

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
                    'autonomous_system_number': self.asn,
                    'autonomous_system_organization' : self.asorganisation,
                    'datasource': self.datasource }
    
@oc.logging.with_logger()
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
        raise NotImplementedError( f"{type(self)}.desktop")

@oc.logging.with_logger()
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
            self.logger.warning( f"IpAddr {ipAddr} not found in Active Directory site/subnet" )

        return location
    

@oc.logging.with_logger()
class ODLocatorPublicInternet( ODLocatorBase ):
    def __init__(self):
        super().__init__()
        self._datasource = 'GeoLite2'
        self.reader_city = None
        self.reader_asn = None
        try:
            self.reader_city = geoip2.database.Reader('/usr/share/geolite2/GeoLite2-City.mmdb')
            self.reader_asn = geoip2.database.Reader('/usr/share/geolite2/GeoLite2-ASN.mmdb')
        except Exception as e:
            self.logger.error( 'geoip2.database.Reader error in open file /usr/share/geolite2/GeoLite2-Country.mmdb')
            self.logger.error( e )

    def locate( self, ipAddr ):        
        self.logger.debug('Looking for ipAddr location %s', ipAddr)
        location = None

        # read 
        try:
            read_city = self.reader_city.city(ipAddr)
            if isinstance( read_city, geoip2.models.City ):   
                try:      
                    location = ODLocation(  country=read_city.country.name, 
                                            country_code=read_city.country.iso_code, 
                                            ipAddr=ipAddr, 
                                            location=[ read_city.location.latitude, read_city.location.longitude ],
                                            timezone=read_city.location.time_zone,
                                            datasource = self.datasource,
                                            resolved=True )
                except: 
                    self.logger.error( e )
        except Exception as e:
            self.logger.error( e )

        # read ASN
        try:
            read_asn = self.reader_asn.asn(ipAddr)
            if isinstance( location, ODLocation) and isinstance( read_asn, geoip2.models.ASN):
                location._asn = read_asn.autonomous_system_number
                location._asorganisation = read_asn.autonomous_system_organization
        except Exception as e:
            self.logger.error( e )

        return location