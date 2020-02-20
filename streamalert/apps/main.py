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

from streamalert.apps import StreamAlertApp


def handler(event, context):
    """Main lambda handler use as the entry point

    Args:
        event (dict): Event object that can potentially contain details on what to
            during this invocation. An example of this is the 'invocation_type' key
            that is used as an override to allow for successive invocations (and in
            the future, support for historical invocations)
        context (LambdaContxt): AWS LambdaContext object
    """
    StreamAlertApp.get_app(event['app_type'])(event, context).gather()
