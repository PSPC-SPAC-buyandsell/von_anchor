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

from random import choice
from string import printable
from von_agent.util import encode, decode

import pytest


#noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_codec():
    for plen in range(0, 1025):
        plain = ''.join(choice(printable) for _ in range(plen))
        enc = encode(plain)
        dec = decode(enc)
        assert plain == dec

    for plain in (None, -5, 0, 1024, 2**32 - 1, 2**32, 2**32 + 1):
        enc = encode(plain)
        dec = decode(enc)
        assert str(plain) == dec if plain is not None else plain == dec
