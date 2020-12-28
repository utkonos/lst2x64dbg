#!/usr/bin/env python3
# Copyright 2019, 2020 Robert Simmons
"""A setuptools based setup module.

See:
https://packaging.python.org/guides/distributing-packages-using-setuptools/
https://github.com/pypa/sampleproject
"""
import pathlib
from setuptools import find_packages, setup

here = pathlib.Path().cwd()

# Get the long description from the README file
with here.joinpath('README.md').open(encoding='utf-8') as fh:
    long_description = fh.read()

setup(
    name='lst2x64dbg',
    version='1.2.0',
    description='Extract labels from IDA, Ghidra, Binary Ninja, Relyze, and Radare2 then export x64dbg database.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/utkonos/lst2x64dbg',
    author='Robert Simmons',
    author_email='utkonos@malwarolo.gy',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Information Technology',
        'Topic :: Security',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3 :: Only',
    ],
    keywords='x64dbg x32dbg ida idafree ghidra binaryninja relyze radare2 reverseengineering debugger',
    packages=find_packages(exclude=['images']),
    python_requires='>=3.7',
    entry_points={
        'console_scripts': [
            'lst2x64dbg=lst2x64dbg.command_line:lst2x64dbg',
            'ghidra2x64dbg=lst2x64dbg.command_line:ghidra2x64dbg',
            'binja2x64dbg=lst2x64dbg.command_line:binja2x64dbg',
            'relyze2x64dbg=lst2x64dbg.command_line:relyze2x64dbg'
        ],
    },
    project_urls={
        'Bug Reports': 'https://github.com/utkonos/lst2x64dbg/issues',
        'Source': 'https://github.com/utkonos/lst2x64dbg',
    },
)
