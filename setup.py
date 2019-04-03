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


import os
from os.path import dirname, join, realpath
from setuptools import setup, find_packages
from sys import stderr


pkg_name = 'von_anchor'
with open(join(dirname(__file__), 'VERSION.txt')) as fh_version:
    release = fh_version.read().strip()


def parse_requirements(filename):
    """
    Load requirements from a pip requirements file.

    :param filename: file name with requirements to parse
    """

    try:
        with open(filename) as fh_req:
            return [line.strip() for line in fh_req if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print('File not found: {}'.format(realpath(filename)), file=stderr)
        raise


setup(
    name=pkg_name,
    version=release,
    packages=find_packages(exclude=['test']),
    description='VON anchors',
    entry_points={
        'console_scripts': [
            'von_anchor_setnym = von_anchor.op.setnym:main'
        ]
    },
    license='Apache Software License',
    author='PSPS-SPAC',
    author_email='stephen.klump@becker-carroll.com',
    url='https://github.com/PSPC-SPAC-buyandsell/{}'.format(pkg_name),
    download_url='https://github.com/PSPC-SPAC-buyandsell/{}/archive/{}.tar.gz'.format(pkg_name, release),
    keywords=['VON', 'SRI', 'anchor', 'The Org Book', 'indy'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3.5',
    ],
    python_requires='>=3.5',
    install_requires=parse_requirements('requirements.txt'),
)
