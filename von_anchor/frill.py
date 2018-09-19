"""
Copyright 2017-2018 Government of Canada - Public Services and Procurement Canada - buyandsell.gc.ca

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


import json

from enum import IntEnum
from pprint import pformat
from typing import Any


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
