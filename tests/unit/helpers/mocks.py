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
from collections import namedtuple

from cbapi.response import BannedHash, Binary


class MockCBAPI:
    """Mock for CbResponseAPI"""

    class MockBannedHash:
        """Mock for cbapi.response.BannedHash"""

        def __init__(self):
            self.enabled = True
            self.md5hash = None
            self.text = ''

        @staticmethod
        def save():
            return True

    class MockBinary:
        """Mock for cbapi.response.Binary"""

        def __init__(self, banned, enabled, md5):
            self._banned = banned
            self._enabled = enabled
            self.md5 = md5

        @property
        def banned(self):
            """Indicates whether binary is banned"""
            if self._banned:
                return namedtuple('MockBanned', ['enabled'])(self._enabled)
            return False

    def __init__(self, **kwargs):
        pass

    @staticmethod
    def create(model):
        """Create banned hash"""
        if model == BannedHash:
            return MockCBAPI.MockBannedHash()

    @staticmethod
    def select(model, file_hash):
        if model == Binary:
            if file_hash == 'BANNED_ENABLED_HASH':
                return MockCBAPI.MockBinary(banned=True, enabled=True, md5=file_hash)
            if file_hash == 'BANNED_DISABLED_HASH':
                return MockCBAPI.MockBinary(banned=True, enabled=False, md5=file_hash)
            return MockCBAPI.MockBinary(banned=False, enabled=False, md5=file_hash)
        if model == BannedHash:
            return MockCBAPI.MockBannedHash()
