#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name='dnsproxy',
    version='1.1',
    description='dns proxy / rewriting daemon',
    author='Pascal Peltriaux',
    author_email='pascal.peltriaux@servicenow.com',
    packages=find_packages(),
    url = 'https://gitlab.service-now.com/pascal.peltriaux/dnsproxy',
    license='GPL',
    install_requires=[
        'plogger>=0.1',
        'python-daemon'
    ],
    dependency_links=['git+https://gitlab.service-now.com/pascal.peltriaux/plogger.git#egg=plogger-0.1'],
    entry_points={
        'console_scripts': ['dnsproxy = dnsproxy.dnsproxy:main'],
    })
