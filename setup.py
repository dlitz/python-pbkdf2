#!/usr/bin/env python

# Use setuptools, if available.  Otherwise, fall back to distutils.
try:
    from setuptools import setup
except ImportError:
    import sys
    sys.stderr.write("warning: Proceeding without setuptools\n")
    from distutils.core import setup

from pbkdf2 import __version__

setup(
    name='pbkdf2',
    py_modules=['pbkdf2'],
    version=__version__,
    test_suite='test',
    description='PKCS#5 v2.0 PBKDF2 Module',
    author='Dwayne C. Litzenberger',
    author_email='dlitz@dlitz.net',
    url='http://www.dlitz.net/software/python-pbkdf2/',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Topic :: Security :: Cryptography',
    ],
    long_description="""\
This module implements the password-based key derivation function, PBKDF2, specified in RSA PKCS#5 v2.0.
""")
