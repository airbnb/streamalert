"""
Copyright 2017-present Airbnb, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
from os import environ as env

from botocore import client

# Set a boto connect and read timeout in an attempt to shorten the time it takes to
# send to firehose. This will effectively cause retries to happen quicker
BOTO_TIMEOUT = 5

# Read the region from the environment (typically Lambda env variables)
REGION = env.get('AWS_REGION') or env.get('AWS_DEFAULT_REGION') or 'us-east-1'


def default_config(timeout=BOTO_TIMEOUT, region=REGION):
    return client.Config(connect_timeout=timeout,
                         read_timeout=timeout,
                         region_name=region or REGION)
