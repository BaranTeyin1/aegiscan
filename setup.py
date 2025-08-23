#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name='aegiscan',
    version='0.1.0',
    packages=find_packages(where='.', exclude=['tests']),
    include_package_data=True,
    install_requires=[
        'PyYAML',
        'sarif_om',
        'colorama', # Added for colored CLI output
    ],
    entry_points={
        'console_scripts': [
            'aegiscan=aegiscan.cli.cli:main',
        ],
    },
    author='Your Name',
    author_email='your.email@example.com',
    description='A rule-based SAST tool for Python code.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/yourusername/aegiscan',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Security',
    ],
    python_requires='>=3.8',
)
