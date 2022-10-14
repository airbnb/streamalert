"""
Copyright 2017-present, Airbnb Inc.
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

import base64

from streamalert.alert_processor.outputs.jira import JiraOutput
from streamalert.alert_processor.outputs.output_base import StreamAlertOutput
from streamalert.shared.logger import get_logger

LOGGER = get_logger(__name__)


# JIRA V2 Output
# This is a subclass of the JIRA output, but with a different set of rest api
# endpoints supporting the API v2 auth method as cookie based auth is deprecated.
# within the Jira Cloud offering.
# ------------------------------------------------------------------------------
@StreamAlertOutput
class JiraSaaSOutput(JiraOutput):
    """
    JiraSaaSOutput handles all alert dispatching for Jira SaaS.
    and is a subclass of the "JiraOutput" dispatcher which is typically used for on-prem Jira."""
    __service__ = 'jira-v2'

    def _get_headers(self):
        """Instance method used to pass the default headers plus the auth cookie"""
        return dict(self._get_default_headers(), **{'Authorization': self._auth_cookie})

    def _establish_session(self, username, password):
        return f'Basic {base64.b64encode(f"{username}:{password}".encode()).decode()}'
