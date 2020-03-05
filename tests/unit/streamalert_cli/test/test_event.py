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
from mock import Mock, patch

from nose.tools import assert_equal, nottest

from streamalert_cli.test.event import TestEvent
from tests.unit.streamalert_cli.test.helpers import (
    basic_test_event_data,
    basic_test_file_json,
)

TestEvent = nottest(TestEvent)


class TestConfigLoading:
    """Test config loading logic with a mocked filesystem."""
    # pylint: disable=no-self-use
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
        assert_equal(self._default_event.data, {'key': 'value'})

    def test_override_record(self):
        """StreamAlert CLI - TestEvent Override Record` Property"""
        assert_equal(self._default_event.override_record, None)

    def test_description(self):
        """StreamAlert CLI - TestEvent Description Property"""
        assert_equal(self._default_event.description, 'Integration test event for unit testing')

    def test_log(self):
        """StreamAlert CLI - TestEvent Log Property"""
        assert_equal(self._default_event.log, 'misc_log_type')

    def test_service(self):
        """StreamAlert CLI - TestEvent Service Property"""
        assert_equal(self._default_event.service, 'unit-test-service')

    def test_source(self):
        """StreamAlert CLI - TestEvent Source Property"""
        assert_equal(self._default_event.source, 'unit-test-source')

    def test_compress(self):
        """StreamAlert CLI - TestEvent Compress Property"""
        assert_equal(self._default_event.compress, False)

    def test_trigger_rules(self):
        """StreamAlert CLI - TestEvent Trigger Rules Property"""
        assert_equal(self._default_event.trigger_rules, ['misc_rule'])

    def test_classify_only(self):
        """StreamAlert CLI - TestEvent Classify Only Property"""
        assert_equal(self._default_event.classify_only, False)

    def test_skip_publishers(self):
        """StreamAlert CLI - TestEvent Skip Publishers Property"""
        assert_equal(self._default_event.skip_publishers, False)

    def test_apply_defaults(self):
        """StreamAlert CLI - TestEvent Apply Defaults"""
        override_event = TestEvent(basic_test_event_data(
            override_data={'override': 'test'}
        ))

        # pylint: disable=protected-access
        override_event._apply_defaults(self.basic_config())

        # Ensure the right key was "overridden"
        assert_equal(override_event._event['data'], {'default': '', 'override': 'test'})

    def test_apply_helpers(self):
        """StreamAlert CLI - TestEvent Apply Helpers"""
        # pylint: disable=protected-access
        # Swap out the key's data with a helper identifier
        self._default_event._event['data']['key'] = '<helper:last_hour>'

        with patch('time.time') as time_mock:
            time_mock.return_value = 300  # will have 60 subtracted from it
            self._default_event._apply_helpers()

        assert_equal(self._default_event._event['data']['key'], '240')

    def test_apply_service_template_s3(self):
        """StreamAlert CLI - TestEvent Apply Service Template, S3"""
        # pylint: disable=protected-access
        s3_event = TestEvent(basic_test_event_data(service='s3'))
        result = s3_event._apply_service_template('')
        assert_equal('s3' in result, True)

    def test_apply_service_template_kinesis(self):
        """StreamAlert CLI - TestEvent Apply Service Template, Kinesis"""
        # pylint: disable=protected-access
        kinesis_event = TestEvent(basic_test_event_data(service='kinesis'))
        result = kinesis_event._apply_service_template('')
        assert_equal('kinesis' in result, True)

    def test_apply_service_template_kinesis_compressed(self):
        """StreamAlert CLI - TestEvent Apply Service Template, Kinesis Compressed"""
        # pylint: disable=protected-access
        event = basic_test_event_data(service='kinesis')
        event['compress'] = True
        kinesis_event = TestEvent(event)
        result = kinesis_event._apply_service_template(b'test')
        assert_equal(result['kinesis']['data'], b'eJwrSS0uAQAEXQHB')

    def test_apply_service_template_sns(self):
        """StreamAlert CLI - TestEvent Apply Service Template, SNS"""
        # pylint: disable=protected-access
        sns_event = TestEvent(basic_test_event_data(service='sns'))
        result = sns_event._apply_service_template('')
        assert_equal('Sns' in result, True)

    def test_apply_service_template_apps(self):
        """StreamAlert CLI - TestEvent Apply Service Template, App"""
        # pylint: disable=protected-access
        app_event = TestEvent(basic_test_event_data(service='streamalert_app'))
        result = app_event._apply_service_template('')
        assert_equal('streamalert_app' in result, True)

