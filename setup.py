from distutils.core import setup


name = 'von_agent'
version = '0.0.0'

setup(
    name = name,
    packages = [name],
    version = version,
    description = 'VON agents',
    author = 'PSPS-SPAC',
    author_email = 'stephen.klump@becker-carroll.com',
    url = 'https://github.com/PSPC-SPAC-buyandsell/{}'.format(name),
    download_url = 'https://github.com/PSPC-SPAC-buyandsell/{}/archive/{}.tar.gz'.format(name, version),
    keywords = ['VON', 'SRI', 'agent', 'The Org Book', 'indy'],
    classifiers = [],
)
