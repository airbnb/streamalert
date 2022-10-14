"""
Copyright 2017-present Airbnb, Inc.

Licensed under the Apache License, Version 2.0 (the 'License');
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an 'AS IS' BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
from unittest.mock import patch

import pytest

from streamalert_cli.test.event import TestEvent
from tests.unit.streamalert_cli.test.helpers import basic_test_event_data

TestEvent = pytest.mark.usefixtures('patcher')(TestEvent)


class TestTestEvent:
    """Test the TestEvent class"""
    # pylint: disable=no-self-use,protected-access

    def setup(self):
        # pylint: disable=attribute-defined-outside-init
        self._default_event = TestEvent(basic_test_event_data())

    @staticmethod
    def basic_config():
        return {
            'logs': {
                'misc_log_type': {
                    'schema': {
                        'key': 'string'
                    }
                },
                'override_log_type': {
                    'schema': {
                        'default': 'string',
                        'override': 'string'
                    }
                }
            }
        }

    def test_data(self):
        """StreamAlert CLI - TestEvent Data Property"""
        assert self._default_event.data == {'key': 'value'}

    def test_override_record(self):
        """StreamAlert CLI - TestEvent Override Record` Property"""
        assert self._default_event.override_record is None

    def test_description(self):
        """StreamAlert CLI - TestEvent Description Property"""
        assert self._default_event.description == 'Integration test event for unit testing'

    def test_log(self):
        """StreamAlert CLI - TestEvent Log Property"""
        assert self._default_event.log == 'misc_log_type'

    def test_service(self):
        """StreamAlert CLI - TestEvent Service Property"""
        assert self._default_event.service == 'unit-test-service'

    def test_source(self):
        """StreamAlert CLI - TestEvent Source Property"""
        assert self._default_event.source == 'unit-test-source'

    def test_compress(self):
        """StreamAlert CLI - TestEvent Compress Property"""
        assert self._default_event.compress == False

    def test_trigger_rules(self):
        """StreamAlert CLI - TestEvent Trigger Rules Property"""
        assert self._default_event.trigger_rules == ['misc_rule']

    def test_classify_only(self):
        """StreamAlert CLI - TestEvent Classify Only Property"""
        assert self._default_event.classify_only == False

    def test_skip_publishers(self):
        """StreamAlert CLI - TestEvent Skip Publishers Property"""
        assert self._default_event.skip_publishers == False

    def test_is_valid(self):
        """StreamAlert CLI - TestEvent Is Valid Property"""
        assert self._default_event.is_valid(self.basic_config())

    def test_is_valid_invalid_type(self):
        """StreamAlert CLI - TestEvent Is Valid Property, Invalid Type"""
        self._default_event._event = []  # invalid data type

        assert self._default_event.is_valid(self.basic_config()) == False
        assert (
            self._default_event.error ==
            'Invalid type for event: <class \'list\'>; should be dict')

    def test_is_valid_missing_key(self):
        """StreamAlert CLI - TestEvent Is Valid Property, Missing Required Key"""
        del self._default_event._event['log']  # remove required key

        assert self._default_event.is_valid(self.basic_config()) == False
        assert self._default_event.error == 'Missing required key(s) in test event: \'log\''

    def test_is_valid_missing_data(self):
        """StreamAlert CLI - TestEvent Is Valid Property, Missing Data or Override"""
        del self._default_event._event['data']  # remove both of the data keys

        assert self._default_event.is_valid(self.basic_config()) == False
        assert (
            self._default_event.error ==
            'Test event must contain either \'data\' or \'override_record\'')

    def test_is_valid_no_trigger_rules(self):
        """StreamAlert CLI - TestEvent Is Valid Property, Missing Rules"""
        # remove key that is required if NOT classify_only
        del self._default_event._event['trigger_rules']

        assert self._default_event.is_valid(self.basic_config()) == False
        assert (
            self._default_event.error ==
            'Test events that are not \'classify_only\' should have \'trigger_rules\' defined')

    def test_is_valid_no_log(self):
        """StreamAlert CLI - TestEvent Is Valid Property, No Log Schema in Config"""
        # update the log key to one that is not defined in the config's logs
        self._default_event._event['log'] = 'not_a_log'

        assert self._default_event.is_valid(self.basic_config()) == False
        assert (
            self._default_event.error ==
            'No defined schema in config for log type: not_a_log')

    @patch('streamalert_cli.test.event.LOGGER.warning')
    def test_is_valid_extra_keys(self, log_mock):
        """StreamAlert CLI - TestEvent Is Valid Property, Extra Keys"""
        # add an extra random key
        self._default_event._event['extra_thing'] = True

        assert self._default_event.is_valid(self.basic_config())
        log_mock.assert_called_with(
            'Additional unnecessary keys in test event: %s',
            '\'extra_thing\''
        )

    def test_format_test_record_invalid_data(self):
        """StreamAlert CLI - TestEvent Format Test Record, Invalid Data"""
        self._default_event._event['data'] = 100  # invalid data type
        result = self._default_event.format_test_record(None)

        assert result == False
        assert self._default_event.error == 'Invalid data type: <class \'int\'>'

    def test_format_test_record_invalid_service(self):
        """StreamAlert CLI - TestEvent Format Test Record, Invalid Service"""
        self._default_event._event['service'] = 'foobar'  # invalid service value
        result = self._default_event.format_test_record(None)

        assert result == False
        assert self._default_event.error == 'Unsupported service: foobar'

    def test_apply_service_template_s3(self):
        """StreamAlert CLI - TestEvent Apply Service Template, S3"""
        s3_event = TestEvent(basic_test_event_data(service='s3'))
        result = s3_event._apply_service_template('')
        assert 's3' in result

    def test_apply_service_template_kinesis(self):
        """StreamAlert CLI - TestEvent Apply Service Template, Kinesis"""
        kinesis_event = TestEvent(basic_test_event_data(service='kinesis'))
        result = kinesis_event._apply_service_template('')
        assert 'kinesis' in result

    def test_apply_service_template_kinesis_compressed(self):
        """StreamAlert CLI - TestEvent Apply Service Template, Kinesis Compressed"""
        event = basic_test_event_data(service='kinesis')
        event['compress'] = True
        kinesis_event = TestEvent(event)
        result = kinesis_event._apply_service_template(b'test')
        assert result['kinesis']['data'] == b'eJwrSS0uAQAEXQHB'

    def test_apply_service_template_sns(self):
        """StreamAlert CLI - TestEvent Apply Service Template, SNS"""
        sns_event = TestEvent(basic_test_event_data(service='sns'))
        result = sns_event._apply_service_template('')
        assert 'Sns' in result

    def test_apply_service_template_apps(self):
        """StreamAlert CLI - TestEvent Apply Service Template, App"""
        app_event = TestEvent(basic_test_event_data(service='streamalert_app'))
        result = app_event._apply_service_template('')
        assert 'streamalert_app' in result

    def test_apply_helpers(self):
        """StreamAlert CLI - TestEvent Apply Helpers"""
        # Swap out the key's data with a helper identifier
        self._default_event._event['data']['key'] = '<helper:last_hour>'

        with patch('time.time') as time_mock:
            time_mock.return_value = 300  # will have 60 subtracted from it
            self._default_event._apply_helpers()

        assert self._default_event._event['data']['key'] == '240'

    def test_apply_defaults(self):
        """StreamAlert CLI - TestEvent Apply Defaults"""
        override_event = TestEvent(basic_test_event_data(
            override_data={'override': 'test'}
        ))

        override_event._apply_defaults(self.basic_config())

        # Ensure the right key was "overridden"
        assert override_event._event['data'] == {'default': '', 'override': 'test'}
