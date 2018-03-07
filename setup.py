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

import os
from setuptools import setup


pkg_name = 'von_agent'
version = '0.5.0'


setup(
    name=pkg_name,
    packages=[
        pkg_name,
        '{}.proto'.format(pkg_name)
    ],
    version=version,
    description='VON agents',
    license='Apache Software License',
    author='PSPS-SPAC',
    author_email='stephen.klump@becker-carroll.com',
    url='https://github.com/PSPC-SPAC-buyandsell/{}'.format(pkg_name),
    download_url='https://github.com/PSPC-SPAC-buyandsell/{}/archive/{}.tar.gz'.format(pkg_name, version),
    keywords=['VON', 'SRI', 'agent', 'The Org Book', 'indy'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3.5',
    ],
    python_requires='>=3.5',
    install_requires=[
        'base58',
        'python3-indy',
        'requests',
        'chardet',
        'certifi',
        'jsonschema'
    ],
)
