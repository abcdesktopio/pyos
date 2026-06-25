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
import functools
import os
import subprocess

logger = logging.getLogger(__name__)

class Event(object):
    """Event class to manage events and handlers

    Usage:
        event = Event()
        def handler(source, *args, **kwargs):
            print(f"Event triggered by {source} with args: {args} and kwargs: {kwargs}")
        event += handler  # Add handler to the event
        event("Source", 1, 2, key="value")  # Trigger the event

    """

    def __init__(self):
        """Initialize the Event with an empty list of handlers."""
        self._handlers = list()

    def __call__(self, source, *args, **kwargs):
        """Trigger the event and call all registered handlers with the given arguments."""
        for h in self._handlers: 
            h(source, *args, **kwargs)

    def __add__(self,other):
        """Add a handler to the event. The handler must be callable."""
        if callable(other) is False: 
            raise ValueError('Event handler must be callable')
        if other not in self._handlers: 
            self._handlers.append(other)
        return self

    def __sub__(self,other):
        """Remove a handler from the event."""
        if other in self._handlers: 
            self._handlers.remove(other)
        return self

    def __repr__(self):
        """Return a string representation of the Event, showing its class name and the list of handlers."""
        return type(self).__name__ + repr(self._handlers)

    def __len__(self):
        """Return the number of handlers registered to the event."""
        return len(self._handlers)


def get_class(path:str, class_name:str=None):
    """Get a class from a module path and an optional class name. If the class name is not provided, it will be inferred from the last part of the path.
    Args:
        path (str): The module path to import the class from.
        class_name (str, optional): The name of the class to import. If not provided, it will be inferred from the last part of the path.
    Returns:
        type: The class object imported from the specified module path. If the class name is not provided, it will be inferred from the last part of the path.
    Raises:
        ImportError: If the module cannot be imported or the class cannot be found in the module.
    """
    if not class_name:
        parts = path.split('.')
        class_name  = parts.pop()
        path = '.'.join(parts)

    return getattr(importlib.import_module(path), class_name)


def get_setting(obj:object, path:str, default=None):
    """ Get a setting from an object using a dot-separated path. The path can contain dictionary keys, list indices, or object attributes.
    Args:
        obj: The object to get the setting from.
        path: The dot-separated path to the setting.
        default: The default value to return if the setting is not found.
    """
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

def execproc(command,environment:dict={},stdout=subprocess.PIPE,timeout:int=60,input=None, encoding='utf8'):
    """Execute a command in a subprocess and return the output and error.
    Args:
        command: The command to execute.
        environment: A dictionary of environment variables to set for the subprocess.
        stdout: The standard output configuration for the subprocess.
        timeout: The timeout in seconds for the subprocess.
        input: The input to pass to the subprocess.
        encoding: The encoding to use for the subprocess output.
    Returns:
        tuple: A tuple containing the return code and the output of the subprocess. If the subprocess times out or encounters an error, the return code will be None and the output will contain the exception.
    """
    try:
        env = os.environ.copy() # default env
        if type(environment) is dict and len(environment) > 0: 
           env.update(environment)

        proc = subprocess.run(command, stdout=subprocess.PIPE, input=input, timeout=timeout, env=env, encoding=encoding)
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
