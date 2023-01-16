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
import cherrypy
from oc.cherrypy import Results
import oc.od.locator
from oc.od.base_controller import BaseController
import oc.od.tracker

logger = logging.getLogger(__name__)

@oc.logging.with_logger()
class TrackerController(BaseController):

    def __init__(self, config_controller=None):
        super().__init__(config_controller)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
 
    def issue(self):
        """[summary]
        """
        (auth, user) = self.validate_env()

        arguments   = cherrypy.request.json
        myjira      = oc.od.tracker.jiraclient()
        summary     = arguments.get('summary', 'summary')
        description = arguments.get('description', 'description') 
        issuetype   = arguments.get('issue', { 'name': 'Bug' }) 
        new_issue   = myjira.issue( description=description, summary=summary, issuetype=issuetype )
        return Results.success(result=new_issue)