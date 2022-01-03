#!/usr/bin/env python

import io
import os
import glob
from setuptools import setup, find_packages

with io.open('README.rst', encoding='UTF-8') as f:
    long_description = f.read()

with io.open('VERSION', encoding='UTF-8') as f:
    VERSION = f.read()

HOMEPAGE = 'https://blackfire.io'
NAME = "blackfire"

CLASSIFIERS = [
    'Development Status :: 5 - Production/Stable',
    'Environment :: Console',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: MIT License',
    'Programming Language :: Python',
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3.4',
    'Programming Language :: Python :: 3.5',
    'Programming Language :: Python :: 3.6',
    'Programming Language :: Python :: 3.7',
    'Programming Language :: Python :: 3.8',
    'Programming Language :: Python :: 3.9',
    'Programming Language :: Python :: 3.10',
    'Programming Language :: Python :: Implementation :: CPython',
    'Operating System :: OS Independent',
    'Topic :: Software Development :: Libraries',
    'Topic :: Software Development :: Libraries :: Python Modules',
]

setup(
    name=NAME,
    version=VERSION,
    author="Blackfire.io",
    author_email="support@blackfire.io",
    py_modules=[os.path.splitext(f)[0] for f in glob.glob("*.py")],
    packages=find_packages(),
    data_files=[
        ('', ['VERSION', 'LICENSE']),
    ],
    description="Blackfire Python SDK",
    long_description=long_description,
    long_description_content_type='text/markdown',
    keywords="",
    classifiers=CLASSIFIERS,
    url=HOMEPAGE,
)
