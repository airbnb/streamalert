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
from nose.tools import raises

from app_integrations.exceptions import AppIntegrationConfigError
from app_integrations.main import handler
from tests.unit.app_integrations.test_helpers import get_mock_context


@raises(AppIntegrationConfigError)
def test_handler():
    """App Integration - Test Handler"""
    handler(None, get_mock_context())
