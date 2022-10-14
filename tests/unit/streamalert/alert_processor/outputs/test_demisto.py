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
# pylint: disable=no-self-use,unused-argument,attribute-defined-outside-init,protected-access
from collections import OrderedDict
from datetime import datetime
from unittest.mock import MagicMock, Mock, patch

from streamalert.alert_processor.helpers import compose_alert
from streamalert.alert_processor.outputs.demisto import (
    DemistoOutput, DemistoRequestAssembler)
from streamalert.alert_processor.outputs.output_base import \
    OutputRequestFailure
from tests.unit.streamalert.alert_processor.helpers import get_alert

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
            },
            {
                "integer": 0,
            },
            {
                "bool": True,
            },
        ]
    }
}

# Order matters in this test!
EXPECTED_LABELS_FOR_SAMPLE_ALERT = [
    {'type': 'cluster', 'value': ''},
    {'type': 'context.demisto.baz', 'value': 'buzz'},
    {'type': 'context.demisto.deepArray[0].key', 'value': 'value'},
    {'type': 'context.demisto.deepArray[1].key', 'value': 'value2'},
    {'type': 'context.demisto.deepArray[2].integer', 'value': '0'},
    {'type': 'context.demisto.deepArray[3].bool', 'value': 'True'},
    {'type': 'context.demisto.foo', 'value': 'bar'},
    {'type': 'created', 'value': '2019-01-01T00:00:00.000000Z'},
    {'type': 'id', 'value': '79192344-4a6d-4850-8d06-9c3fef1060a4'},
    {'type': 'log_source', 'value': 'carbonblack:binarystore.file.added'},
    {'type': 'log_type', 'value': 'json'},
    {'type': 'outputs[0]', 'value': 'slack:unit_test_channel'},
    {'type': 'record.cb_server', 'value': 'cbserver'},
    {'type': 'record.compressed_size', 'value': '9982'},
    {'type': 'record.file_path',
     'value': '/tmp/5DA/AD8/0F9AA55DA3BDE84B35656AD8911A22E1.zip'},
    {'type': 'record.md5', 'value': '0F9AA55DA3BDE84B35656AD8911A22E1'},
    {'type': 'record.node_id', 'value': '1'},
    {'type': 'record.size', 'value': '21504'},
    {'type': 'record.timestamp', 'value': '1496947381.18'},
    {'type': 'record.type', 'value': 'binarystore.file.added'},
    {'type': 'rule_description', 'value': 'Info about this rule and what actions to take'},
    {'type': 'rule_name', 'value': 'cb_binarystore_file_added'},
    {'type': 'source_entity', 'value': 'corp-prefix.prod.cb.region'},
    {'type': 'source_service', 'value': 's3'},
    {'type': 'staged', 'value': 'False'},
]


class TestDemistoOutput:
    """Test class for SlackOutput"""
    DESCRIPTOR = 'unit_test_demisto'
    SERVICE = 'demisto'
    OUTPUT = ':'.join([SERVICE, DESCRIPTOR])
    CREDS = {
        'url': 'https://demisto.awesome-website.io',
        'token': 'aaaabbbbccccddddeeeeffff',
    }

    @patch('streamalert.alert_processor.outputs.output_base.OutputCredentialsProvider')
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
        assert isinstance(DemistoOutput.get_user_defined_properties(), OrderedDict)

    @patch('requests.post')
    def test_dispatch(self, request_mock):
        """DemistoOutput - Dispatch Success, Mocked Request Session"""
        mock_response = MagicMock()
        mock_response.status_code = 201
        request_mock.return_value = mock_response

        alert = get_alert(context=SAMPLE_CONTEXT)
        alert.created = datetime(2019, 1, 1)

        success = self._dispatcher.dispatch(alert, self.OUTPUT)

        assert success

        expected_data = {
            'type': 'Unclassified',
            'name': 'cb_binarystore_file_added',
            'owner': 'StreamAlert',
            'playbook': 'Unknown',
            'severity': 0,
            'labels': EXPECTED_LABELS_FOR_SAMPLE_ALERT,
            'customFields': {},
            'details': 'Info about this rule and what actions to take',
            'createInvestigation': True,
        }

        class Matcher:
            def __eq__(self, other):
                return other == expected_data

        request_mock.assert_called_with(
            'https://demisto.awesome-website.io/incident',
            headers={
                'Accept': 'application/json',
                'Content-type': 'application/json',
                'Authorization': 'aaaabbbbccccddddeeeeffff',
            },
            json=Matcher(),
            verify=False,
            timeout=3.05
        )

    @patch('logging.Logger.exception')
    @patch('requests.post')
    @patch('streamalert.alert_processor.outputs.output_base.OutputDispatcher.MAX_RETRY_ATTEMPTS',
           1)
    def test_dispatch_fail(self, request_mock, logger_spy):
        """DemistoOutput - Dispatch Success, Response is Failure"""

        mock_response = MagicMock()
        mock_response.status_code = 400  # bad request
        request_mock.return_value = mock_response

        alert = get_alert(context=SAMPLE_CONTEXT)
        alert.created = datetime(2019, 1, 1)

        success = self._dispatcher.dispatch(alert, self.OUTPUT)

        assert not success

        class Matcher:
            def __eq__(self, other):
                return isinstance(other, OutputRequestFailure)
        logger_spy.assert_called_with('Failed to create Demisto incident: %s.', Matcher())


def test_assemble():
    """DemistoRequestAssembler - assemble"""
    alert = get_alert(context=SAMPLE_CONTEXT)
    alert.created = datetime(2019, 1, 1)

    output = MagicMock(spec=DemistoOutput)
    alert_publication = compose_alert(alert, output, 'asdf')

    request = DemistoRequestAssembler.assemble(alert, alert_publication)

    assert request.incident_name == 'cb_binarystore_file_added'
    assert request.incident_type == 'Unclassified'
    assert request.severity == 0
    assert request.owner == 'StreamAlert'
    assert request.labels == EXPECTED_LABELS_FOR_SAMPLE_ALERT
    assert request.details == 'Info about this rule and what actions to take'
    assert request.custom_fields == {}
    assert request.create_investigation
