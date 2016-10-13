#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name='dnsproxy',
    version='1.1',
    description='dns proxy / rewriting daemon',
    author='Pascal Peltriaux',
    author_email='ppeltriaux@gmail.com',
    packages=find_packages(),
    url = 'https://github.com/ppeltriaux/dnsproxy.git',
    license='GPL',
    install_requires=[
        'plogger>=0.1',
        'python-daemon'
    ],
    dependency_links=['git+https://github.com/ppeltriaux/plogger.git#egg=plogger-0.1'],
    entry_points={
        'console_scripts': ['dnsproxy = dnsproxy.dnsproxy:main'],
    })
