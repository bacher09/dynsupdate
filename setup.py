#!/usr/bin/env python
from setuptools import setup, find_packages
import sys


def lt27():
    v = sys.version_info
    return (v[0], v[1]) < (2, 7)


def lt33():
    v = sys.version_info
    return (v[0], v[1]) < (3, 3)


tests_require = [
    'nose>=1.0',
]


if lt33():
    tests_require.append('mock')
    

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

