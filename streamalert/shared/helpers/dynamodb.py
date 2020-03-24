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
from botocore.exceptions import ClientError


def ignore_conditional_failure(func):
    """Decorator which ignores ClientErrors due to ConditionalCheckFailed.

    Conditional checks prevent Dynamo updates from finishing if the existing state doesn't match
    expectations. For example, if an Alert no longer exists, we don't want to send any other updates

    Args:
        func (function): Function with a conditional Dynamo update call.

    Returns:
        function: Wrapped function which ignores failures due to conditional checks.
    """
    def inner(*args, **kwargs):
        """Ignore ConditionalCheckFailedException"""
        try:
            func(*args, **kwargs)
        except ClientError as error:
            if error.response['Error']['Code'] != 'ConditionalCheckFailedException':
                raise

    return inner
