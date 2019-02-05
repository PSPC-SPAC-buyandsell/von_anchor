"""
Copyright 2017-2019 Government of Canada - Public Services and Procurement Canada - buyandsell.gc.ca

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""


import asyncio
import json
import re

from configparser import ConfigParser
from enum import IntEnum
from os.path import expandvars, isfile
from pprint import pformat
from time import time
from typing import Any, Callable, Sequence, Union


def ppjson(dumpit: Any, elide_to: int = None) -> str:
    """
    JSON pretty printer, whether already json-encoded or not

    :param dumpit: object to pretty-print
    :param elide_to: optional maximum length including ellipses ('...')
    :return: json pretty-print
    """

    if elide_to is not None:
        elide_to = max(elide_to, 3) # make room for ellipses '...'
    try:
        rv = json.dumps(json.loads(dumpit) if isinstance(dumpit, str) else dumpit, indent=4)
    except TypeError:
        rv = '{}'.format(pformat(dumpit, indent=4, width=120))
    return rv if elide_to is None or len(rv) <= elide_to else '{}...'.format(rv[0 : elide_to - 3])


def do_wait(coro: Callable) -> Any:
    """
    Perform aynchronous operation; await then return the result.

    :param coro: coroutine to await
    :return: coroutine result
    """

    event_loop = None
    try:
        event_loop = asyncio.get_event_loop()
    except RuntimeError:
        event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(event_loop)
    return event_loop.run_until_complete(coro)


def inis2dict(ini_paths: Union[str, Sequence[str]]) -> dict:
    """
    Take one or more ini files and return a dict with configuration from all,
    interpolating bash-style variables ${VAR} or ${VAR:-DEFAULT}.

    :param ini_paths: path or paths to .ini files
    """

    var_dflt = r'\${(.*?):-(.*?)}'
    def _interpolate(content):
        rv = expandvars(content)
        while True:
            match = re.search(var_dflt, rv)
            if match is None:
                break
            bash_var = '${{{}}}'.format(match.group(1))
            value = expandvars(bash_var)
            rv = re.sub(var_dflt, match.group(2) if value == bash_var else value, rv, count=1)

        return rv

    parser = ConfigParser()

    for ini in [ini_paths] if isinstance(ini_paths, str) else ini_paths:
        if not isfile(ini):
            raise FileNotFoundError('No such file: {}'.format(ini))
        with open(ini, 'r') as ini_fh:
            ini_text = _interpolate(ini_fh.read())
            parser.read_string(ini_text)

    return {s: dict(parser[s].items()) for s in parser.sections()}


class Stopwatch:
    """
    Stopwatch class for troubleshooting lags.
    """

    def __init__(self, digits: int = None):
        """
        Instantiate and start.

        :param digits: number of fractional decimal digits to retain (default to all) by default
        """

        self._mark = [time()] * 2
        self._digits = digits

    def mark(self, digits: int = None) -> float:
        """
        Return time in seconds since last mark, reset, or construction.

        :param digits: number of fractional decimal digits to retain (default as constructed)
        """

        self._mark[:] = [self._mark[1], time()]
        rv = self._mark[1] - self._mark[0]

        if digits is not None and digits > 0:
            rv = round(rv, digits)
        elif digits == 0 or self._digits == 0:
            rv = int(rv)
        elif self._digits is not None and self._digits > 0:
            rv = round(rv, self._digits)

        return rv

    def reset(self) -> float:
        """
        Reset.
        """

        self._mark = [time()] * 2
        return 0.0


class Ink(IntEnum):
    """
    Class encapsulating ink colours for logging.
    """

    BLACK = 30
    RED = 31
    GREEN = 32
    YELLOW = 33
    BLUE = 34
    MAGENTA = 35
    CYAN = 36
    WHITE = 37

    def __call__(self, message: str) -> str:
        """
        Return input message in colour.

        :return: input message in colour
        """

        return '\033[{}m{}\033[0m'.format(self.value, message)
