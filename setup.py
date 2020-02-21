# Copyright 2020-present, Airbnb Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Setup script for StreamAlert"""
import os
import re

from setuptools import find_packages, setup


HERE = os.path.dirname(__file__)
VERSION_RE = re.compile(r'''__version__ = ['"]([0-9.]+)['"]''')
REQUIRES = [
    'aliyun-python-sdk-core==2.13.5',
    'aliyun-python-sdk-actiontrail==2.0.0',
    'backoff==1.8.1',
    'boto3==1.10.7',
    'boxsdk[jwt]==2.6.1',
    'cbapi==1.5.4',
    'google-api-python-client==1.7.11',
    'jmespath==0.9.4',
    'jsonlines==1.2.0',
    'mock==3.0.5',
    'netaddr==0.7.19',
    'pathlib2==2.3.5',
    'policyuniverse==1.3.2.1',
    'requests==2.22.0',
]


def _get_version():
    init = open(os.path.join(HERE, 'streamalert', '__init__.py')).read()
    return VERSION_RE.search(init).group(1)


FILES = [
    (
        'streamalert_{}'.format(d),
        [os.path.join(d, f) for f in files if f.endswith(('.tf', '.md', '.py', '.json'))]
    )
    for folder in ('examples', 'terraform') for d, _, files in os.walk(folder)
]


setup(
    name='streamalert',
    version=_get_version(),
    description='StreamAlert Real-time Log Processing',
    long_description=open(os.path.join(HERE, 'README.rst')).read(),
    author='Airbnb, Inc.',
    author_email='',
    url='',
    entry_points={
        'console_scripts': 'streamalert=streamalert_cli.manage:main'
    },
    install_requires=REQUIRES,
    packages=find_packages(exclude=['tests*']),
    package_data={
        'streamalert_cli': [
            '_infrastructure/*',
        ]
    },
    include_package_data=True,
    zip_safe=True,
    license='Apache 2.0',
    keywords='streamalert real-time log processing',
    classifiers=[
        'Programming Language :: Python :: 3.7',
        'Intended Audience :: Developers',
        'Development Status :: 5 - Production/Stable',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
