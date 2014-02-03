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
    install_packages.append('argparse')
    tests_require.append('unittest2')


setup(
    name='dynsupdate',
    description='Dynamic DNS update like nsupdate',
    install_requires=install_packages,
    tests_require=tests_require,
    packages=find_packages(),
    test_suite="nose.collector",
    entry_points={
        'console_scripts': [
            'dynsupdate = dynsupdate.client:main'
        ]
    },
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Environment :: Console",
        "Topic :: Internet :: Name Service (DNS)",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.2",
        "Programming Language :: Python :: 3.3",
    ],
    license="BSD",
    author='Slava Bacherikov',
    author_email='slava@bacherikov.org.ua',
    version="0.1a"
)
