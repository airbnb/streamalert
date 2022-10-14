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

from streamalert.classifier.parsers import SyslogParser


class TestSyslogParser:
    """Test class for SyslogParser"""
    # pylint: disable=no-self-use,protected-access

    def test_parse(self):
        """Syslog Parser - Parse"""
        options = {
            'schema': {
                'timestamp': 'string',
                'host': 'string',
                'application': 'string',
                'message': 'string'
            }
        }
        data = (
            'Jan 26 19:35:33 vagrant-ubuntu-trusty-64 '
            'sudo: pam_unix(sudo:session): '
            'session opened for user root by (uid=0)'
        )

        expected_record = {
            'timestamp': 'Jan 26 19:35:33',
            'host': 'vagrant-ubuntu-trusty-64',
            'application': 'sudo',
            'message': 'pam_unix(sudo:session): session opened for user root by (uid=0)'
        }

        # get parsed data
        parser = SyslogParser(options)
        result = parser._parse(data)
        assert result == [(expected_record, True)]

    def test_parse_invalid_data(self):
        """Syslog Parser - Parse, Invalid"""
        options = {
            'schema': {
                'timestamp': 'string',
                'host': 'string',
                'application': 'string',
                'message': 'string'
            }
        }
        # Invalid data for syslog record
        data = 'Jan 26 19:35:33 vagrant-ubuntu-trusty-64'

        # get parsed data
        parser = SyslogParser(options)
        result = parser._parse(data)
        assert result == [(data, False)]
