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

import functools

def get_property(obj, path, default=None):
    try:
        return functools.reduce(lambda o,n: getattr(o,n), [obj, *path.split('.')])
    except AttributeError:
        return default


def get_setting(obj, path, default=None):
    def getter(o,n):
        if isinstance(o, dict): 
            return o[n]
        if isinstance(o, list): 
            return o[int(n)]
        return getattr(o,n)

    try:
        return functools.reduce(lambda o,n: getter(o,n), [obj, *path.split('.')])
    except (AttributeError,KeyError,IndexError):
        return default


class ConfigObject(object):
    def __getattr__(self, name):
        return None

    def __str__(self):
        return str(self.__dict__)

    def get_setting(self,path,default):
        return get_setting(self, path,default)

    def get_property(self,path,default):
        return get_property(self, path,default)


class TypeHint(object):
    def __init__(self, type):
        self.type = type

    def get_defaultvalue(self):
        return self.type()


class CollectionTypeHint(TypeHint):
    def __init__(self, element_type,default_value=[]):
        super().__init__(default_value.__class__)
        self.default_value = default_value
        self.element_type = element_type


class ListOf(CollectionTypeHint):
    def __init__(self, element_type):
        super().__init__(element_type)


class DictOf(CollectionTypeHint):
    def __init__(self, element_type, key_type=None):
        super().__init__(element_type, {})
        self.key_type = element_type


    class ConfigObject(object):
        def __init__(self, properties=None):
            if properties: 
                self.__dict__.update(properties)

        def __getattr__(self, name):
            return None

        #def has(self, name):
        #    return name in self

        def __str__(self):
            return str(self.__dict__)

        def __repr__(self):
            return '<' + self.__class__.__name__ + str(self) + '>'

        def __getitem__(self, name):
            return getattr(self, name)

        def __setitem__(self, name, value):
            setattr(self,name, value)

        def get(self, name, default=None):
            value = getattr(self,name)
            return default if value is None else value

        def set(self, name, value):
            setattr(self,name, value)

        def has(self, name):
            return name in self.__dict__ or isinstance(type(self).__dict__.get(name), property)


    class ConfigDict(dict):
        def __getattr__(self, name):
            return self.get(name)

        def __setattr__(self, name, value):
            self[name] = value

        def has(self, name):
            return name in self

        def set(self, name, value):
            self[name] = value