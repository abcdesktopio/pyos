
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

logger = logging.getLogger(__name__)

def getGeoIPdict( ipaddr ):
    logger.debug('Looking for ip data %s', ipaddr)
    mydict = {'location': None, 'ip': ipaddr}
    try:
      import GeoIP
      gi = GeoIP.open("/usr/share/GeoIP/GeoIPCity.dat", GeoIP.GEOIP_STANDARD)
      gir = gi.record_by_addr( ipaddr )
      mydict['country']       = gir.get('country_name')
      mydict['country_code']  = gir.get('country_code')
      mydict['ip']            = ipaddr
      mydict['location']      = [ gir.get('latitude'), gir.get('longitude') ]
      mydict['timezone']      = gir.get('time_zone')
    except Exception as e:
      logger.error('%s', e)

    return mydict