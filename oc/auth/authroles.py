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
import mergedeep


class AuthRoles(dict):
    def __init__(self, entries):
        if isinstance(entries, dict):
            super().__init__(entries)

    def __getattr__(self, name):
        return self.get(name)

    def __getitem__(self, key):
        return getattr(self, key, None)

    def merge(self, newroles):
        if not isinstance(newroles, AuthRoles):
            raise ValueError(f"merge error invalid roles AuthRoles object type {type(newroles)}")
        mergedeep.merge(newroles, self, strategy=mergedeep.Strategy.ADDITIVE)
        return newroles
