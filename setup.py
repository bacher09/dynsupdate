#!/usr/bin/env python
from setuptools import setup, find_packages
import sys


install_packages = []
PY2 = sys.version_info[0] == 2
if PY2:
    install_packages.append('dnspython')
else:
    install_packages.append('dnspython3')


def lt27():
    v = sys.version_info
    return (v[0], v[1]) < (2, 7)


def lt33():
    v = sys.version_info
    return (v[0], v[1]) < (3, 3)


tests_require = [
    'nose>=1.0',
    'coverage'
]


if lt33():
    tests_require.append('mock')


if lt27():
    tests_require.append('unittest2')


setup(
    name='dynsupdate',
    description='Dynamic DNS update like nsupdate',
    install_requires=install_packages,
    tests_require=tests_require,
    packages=find_packages(),
    test_suite="nose.collector"
)
