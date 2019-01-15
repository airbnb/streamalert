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
# pylint: disable=no-self-use,unused-argument,attribute-defined-outside-init,protected-access
from collections import OrderedDict

from requests.exceptions import HTTPError
from mock import patch, Mock, MagicMock
from nose.tools import assert_is_instance, assert_true, assert_false, assert_equal

from stream_alert.alert_processor.outputs.demisto import DemistoOutput, DemistoRequestAssembler

from tests.unit.stream_alert_alert_processor.helpers import get_alert

SAMPLE_CONTEXT = {
    'demisto': {
        'foo': 'bar',
        'baz': 'buzz',
        'deepArray': [
            {
                "key": "value",
            },
            {
                "key": "value2",
            }
        ]
    }
}
EXPECTED_LABELS_FOR_SAMPLE_ALERT = [
    {'type': 'alert.alert_id', 'value': '79192344-4a6d-4850-8d06-9c3fef1060a4'},
    {'type': 'alert.cluster', 'value': None},
    {'type': 'alert.log_type', 'value': 'json'},
    {
        'type': 'alert.record',
        'value': (
            '{"compressed_size": "9982", "node_id": "1", "cb_server": "cbserver",'
            ' "timestamp": "1496947381.18", "md5": '
            '"0F9AA55DA3BDE84B35656AD8911A22E1", "type": '
            '"binarystore.file.added", "file_path": '
            '"/tmp/5DA/AD8/0F9AA55DA3BDE84B35656AD8911A22E1.zip", "size": '
            '"21504"}'
        )
    },
    {'type': 'alert.source', 'value': 'carbonblack:binarystore.file.added'},
    {'type': 'alert.source_entity', 'value': 'corp-prefix.prod.cb.region'},
    {'type': 'alert.source_service', 'value': 's3'},
    {'type': 'context.demisto.baz', 'value': 'buzz'},
    {'type': 'context.demisto.deepArray.[0].key', 'value': 'value'},
    {'type': 'context.demisto.deepArray.[1].key', 'value': 'value2'},
    {'type': 'context.demisto.foo', 'value': 'bar'},
    {'type': 'record.cb_server', 'value': 'cbserver'},
    {'type': 'record.compressed_size', 'value': '9982'},
    {'type': 'record.file_path',
     'value': '/tmp/5DA/AD8/0F9AA55DA3BDE84B35656AD8911A22E1.zip'},
    {'type': 'record.md5', 'value': '0F9AA55DA3BDE84B35656AD8911A22E1'},
    {'type': 'record.node_id', 'value': '1'},
    {'type': 'record.size', 'value': '21504'},
    {'type': 'record.timestamp', 'value': '1496947381.18'},
    {'type': 'record.type', 'value': 'binarystore.file.added'}
]

class TestDemistoOutput(object):
    """Test class for SlackOutput"""
    DESCRIPTOR = 'unit_test_demisto'
    SERVICE = 'demisto'
    OUTPUT = ':'.join([SERVICE, DESCRIPTOR])
    CREDS = {
        'url': 'https://demisto.awesome-website.io',
        'token': 'aaaabbbbccccddddeeeeffff',
    }

    @patch('stream_alert.alert_processor.outputs.output_base.OutputCredentialsProvider')
    def setup(self, provider_constructor):
        """Setup before each method"""
        provider = MagicMock()
        provider_constructor.return_value = provider
        provider.load_credentials = Mock(
            side_effect=lambda x: self.CREDS if x == self.DESCRIPTOR else None
        )

        self._provider = provider
        self._dispatcher = DemistoOutput(None)

    def test_get_user_defined_properties(self):
        """DemistoOutput - User Defined Properties"""
        assert_is_instance(DemistoOutput.get_user_defined_properties(), OrderedDict)


    @patch('requests.sessions.Session.request')
    def test_dispatch(self, request_mock):
        """DemistoOutput - Dispatch Success, Mocked Request Session"""

        # The current DemistoApiClient integration is built over requests.Session
        # This test puts a spy on the requests library and ensures that the correct request
        # parameters are sent, regardless of the integration middleware we use.
        mock_response = MagicMock()
        mock_response.status_code = 201
        request_mock.return_value = mock_response

        success = self._dispatcher.dispatch(get_alert(context=SAMPLE_CONTEXT), self.OUTPUT)

        assert_true(success)

        expected_data = {
            'name': 'StreamAlert Rule Triggered - cb_binarystore_file_added',
            'type': 'unit_test_demisto',
            'severity': 0.5,
            'owner': 'StreamAlert',
            'labels': EXPECTED_LABELS_FOR_SAMPLE_ALERT,
            'details': 'Info about this rule and what actions to take',
            'customFields': {},
            'createInvestigation': True,
        }
        request_mock.assert_called_with(
            'POST',
            'https://demisto.awesome-website.io/incident',
            headers={
                'Accept': 'application/json',
                'Content-type': 'application/json',
                'Authorization': 'aaaabbbbccccddddeeeeffff',
            },
            verify=False,
            json=expected_data
        )

    @patch('logging.Logger.error')
    @patch('requests.sessions.Session.request')
    def test_dispatch_fail(self, request_mock, logger_spy):
        """DemistoOutput - Dispatch Success, Response is Failure"""

        e = HTTPError()
        mock_response = MagicMock()
        mock_response.status_code = 400  # bad request
        mock_response.raise_for_status.side_effect = e
        request_mock.return_value = mock_response

        success = self._dispatcher.dispatch(get_alert(context=SAMPLE_CONTEXT), self.OUTPUT)

        assert_false(success)

        logger_spy.assert_any_call('Failed to create Demisto incident: %s.', e)


class TestDemistoRequestAssembler(object):
    """Test class for DemistoRequestAssembler"""

    def test_assemble(self):
        """DemistoRequestAssembler - assemble"""
        alert = get_alert(context=SAMPLE_CONTEXT)
        descriptor = 'Test Descriptor'

        request = DemistoRequestAssembler.assemble(alert, descriptor)

        assert_equal(request._incident_name, ('StreamAlert Rule Triggered - '
                                              'cb_binarystore_file_added'))
        assert_equal(request._incident_type, 'Test Descriptor')
        assert_equal(request._severity, 0.5)
        assert_equal(request._owner, 'StreamAlert')
        assert_equal(request._labels, EXPECTED_LABELS_FOR_SAMPLE_ALERT)
        assert_equal(request._details, 'Info about this rule and what actions to take')
        assert_equal(request._custom_fields, {})
        assert_equal(request._create_investigation, True)
