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
import base64
import oc.lib

class ODVncPassword():
    """[ODVncPassword]
        ODVncPassword class  
    """
    def __init__(self, defaultvncpassword=None) -> None:
        """[__init__]
            init ODVncPassword class
        Args:
            key ([str]): [cypher key]
            initvncpassword ([str], optional): [default vnc password value]. Defaults to None.
            passwordlen (int, optional): [len of the vnc password if it does not exist]. Defaults to 10.
        """
        #
        # passlength must respect len(labels) <= 63 chars for kubernetes
        # 35 is the max len
        self._passlength = 15
        self._vncpassword = defaultvncpassword

    def make( self ):
        """[make]
            build a vnc password plain text using random value for length 
            self._passlength = 10 bydefault
        Returns:
            [type]: [description]
        """
        self._vncpassword = oc.lib.randomStringwithDigitsAndSymbols( self._passlength )
        return self._vncpassword

    def getplain( self ):
        """[getplain]
            get vnc password plain text
        Returns:
            [str]: [clear vnc password plain text]
        """
        if self._vncpassword is None:
            self.make()
        return self._vncpassword