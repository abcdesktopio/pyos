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
import importlib
import pyclbr
import pkgutil
import functools
import os
import re
import subprocess
from subprocess import run, PIPE
from string import Formatter
import urllib

logger = logging.getLogger(__name__)

class Event(object):
    def __init__(self):
        self._handlers = list()

    def __call__(self, source, *args, **kwargs):
        for h in self._handlers: 
            h(source, *args, **kwargs)

    def __add__(self,other):
        if callable(other) is False: 
            raise ValueError('Event handler must be callable')
        if other not in self._handlers: 
            self._handlers.append(other)
        return self

    def __sub__(self,other):
        if other in self._handlers: 
            self._handlers.remove(other)
        return self

    def __repr__(self):
        return type(self).__name__ + repr(self._handlers)

    def __len__(self):
        return len(self._handlers)


class Lazy(object):
    Undefined = object()

    def __init__(self, initializer): 
        self._value = Lazy.Undefined
        self.initializer = initializer

    @property
    def value(self):
        if self._value is Lazy.Undefined: 
            self._value = self.initializer()
        return self._value

    def __call__(self):
        return self.value

def get_class(path, class_name=None):
    if not class_name:
        parts = path.split('.')
        class_name  = parts.pop()
        path = '.'.join(parts)

    return getattr(importlib.import_module(path), class_name)


def import_classes(package, module_name_filter=None, class_name_filter=None, base_class=None):
    classes = []
    path = importlib.import_module(package).__path__
    logger.debug( "Loading module in directory %s" % path)
    for _filefinder, name, ispkg in pkgutil.iter_modules(importlib.import_module(package).__path__):
        if ispkg or (module_name_filter and not re.match(module_name_filter, name)):
            continue 

        module_name = '.'.join([package, name])
        logger.debug("Importing module '%s'", module_name)
        module = importlib.import_module(module_name)       
        for class_info in pyclbr.readmodule(module_name).values():
   
            if class_name_filter and not re.match(class_name_filter, class_info.name):
                continue

            class_ = getattr(module, class_info.name)
            if base_class and not issubclass(class_, base_class): 
                continue

            classes.append(class_)                

    return classes

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

def execproc(command,environment={},stdout=subprocess.PIPE,timeout=60,input=None, encoding='utf8'):
    try:
        env = os.environ.copy()
        if type(environment) is dict and len(environment) > 0: 
           env.update(environment)

        proc = run(command, stdout=PIPE, input=input, timeout=timeout, env=env, encoding=encoding)
        if not isinstance(proc, subprocess.CompletedProcess):
            return (None, None)

        output = proc.stdout
        line = output.split('\n')

        return (proc.returncode, line)

    # If the process does not terminate after timeout seconds, a TimeoutExpired exception will be raised. 
    # Catching this exception and retrying communication will not lose any output.
    except subprocess.TimeoutExpired as e:
        logger.error(e)
        return (None, e)

    except Exception as e:
        logger.error(e)
        return (None, e)
