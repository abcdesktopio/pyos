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
import oc.od.settings
from jira import JIRA

logger = logging.getLogger(__name__)

@oc.logging.with_logger()
class jiraclient( object ):

    def __init__(self):
        url = oc.od.settings.jira.get('url')
        username = oc.od.settings.jira.get('username')
        apikey = oc.od.settings.jira.get('apikey')
        self.project_id = oc.od.settings.jira.get('project_id')
        self.jira = None
        if all( [ url, self.project_id, username, apikey ]) :
            try:
                self.jira = JIRA( url, basic_auth=(username, apikey) )
            except Exception as e:
                self.logger.error( 'Init jira failed %s', e)
    
    def __del__(self):
        if self.jira:
             self.jira.close()

    def isenable(self):
        if self.jira:
            return True
        return False


    def issue( self, summary, description, issuetype ):
        
        submitissue = None 
        if self.jira is None:
            return submitissue
 
        # make sure that issuetype dict has a name entry
        # if issuetype.get('name') is None:
        issuetype['name'] = 'Bug'

        new_issue = self.jira.create_issue( project=self.project_id, 
                                            summary=summary,
                                            description=description, 
                                            issuetype=issuetype )

        if hasattr( new_issue, 'id' ) and hasattr( new_issue, 'key') :
            submitissue = { 'project': self.project_id, 'id' : new_issue.id, 'key': new_issue.key }
        
        return submitissue