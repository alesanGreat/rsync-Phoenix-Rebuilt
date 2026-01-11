#!/usr/bin/env python3
"""
Setup script for rsync-python

Installation:
    pip install .
    pip install -e .  # Development mode

Distribution:
    python setup.py sdist bdist_wheel
    twine upload dist/*
"""

from setuptools import setup
import re

# Read version from rsync_phoenix_rebuilt.py
with open('rsync_phoenix_rebuilt.py', 'r', encoding='utf-8') as f:
    content = f.read()
    version_match = re.search(r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]', content, re.MULTILINE)
    if version_match:
        version = version_match.group(1)
    else:
        raise RuntimeError("Unable to find version string in rsync_phoenix_rebuilt.py")

# Read long description from README
with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='rsync-python',
    version=version,
    description='Pure Python rsync algorithm implementation - Rolling checksum, delta transfer, block matching. No binary dependencies. Production-ready with 130+ tests. Protocols 20-32 supported. Cross-platform. Zig and PHP versions coming soon.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Alejandro Sanchez',
    author_email='alesangreat@gmail.com',
    url='https://github.com/alesanGreat/rsync-Phoenix-Rebuilt',
    project_urls={
        'Bug Tracker': 'https://github.com/alesanGreat/rsync-Phoenix-Rebuilt/issues',
        'Documentation': 'https://github.com/alesanGreat/rsync-Phoenix-Rebuilt#readme',
        'Source Code': 'https://github.com/alesanGreat/rsync-Phoenix-Rebuilt',
    },
    py_modules=['rsync_phoenix_rebuilt'],
    python_requires='>=3.8',
    install_requires=[
        'xxhash>=3.0.0',
        'lz4>=4.0.0',
        'zstandard>=0.20.0',
    ],
    extras_require={
        'dev': [
            'pytest>=7.0.0',
            'pytest-cov>=4.0.0',
            'mypy>=1.0.0',
            'black>=23.0.0',
            'flake8>=6.0.0',
            'isort>=5.12.0',
        ],
        'docs': [
            'sphinx>=5.0.0',
            'sphinx-rtd-theme>=1.2.0',
        ],
    },
    entry_points={
        'console_scripts': [
            'rsync-phoenix=rsync_phoenix_rebuilt:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Archiving :: Backup',
        'Topic :: System :: Archiving :: Mirroring',
        'Topic :: Utilities',
    ],
    keywords='rsync sync backup delta algorithm compression file-transfer',
    license='GPL-3.0-or-later',
    platforms=['any'],
    zip_safe=False,
)
