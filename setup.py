import os
from setuptools import setup


pkg_name = 'von_agent'
version = '0.0.0-dev-2'


setup(
    name=pkg_name,
    packages=[pkg_name],
    package_dir={pkg_name: pkg_name},
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
        'certifi'
    ],
)
