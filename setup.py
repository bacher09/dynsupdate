#!/usr/bin/env python
from setuptools import setup, find_packages


def lt27():
    import sys
    v = sys.version_info
    return (v[0], v[1]) < (2, 7)
    

tests_require = [
    'nose>=1.0',
    'mock',
]


if lt27():
    tests_require.append('unittest2')


setup(
    name='dynsupdate',
    description='Dynamic DNS update like nsupdate',
    install_requires=[
        'dnspython',
    ],
    tests_require=tests_require,
    packages=find_packages(),
    test_suite="nose.collector"
)

