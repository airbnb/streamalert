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
# pylint: disable=protected-access,too-many-public-methods
import json

from mock import call, patch
from nose.tools import (
    assert_equal,
    assert_false,
    assert_is_instance,
    assert_list_equal,
    assert_true
)

import stream_alert.rule_processor.classifier as sa_classifier
from stream_alert.rule_processor.config import load_config
from stream_alert.rule_processor.payload import load_stream_payload
from tests.unit.stream_alert_rule_processor.test_helpers import make_kinesis_raw_record


class TestStreamClassifier(object):
    """Test class for StreamClassifier"""

    def __init__(self):
        self.classifier = None

    def setup(self):
        """Setup before each method"""
        config = load_config('tests/unit/conf')
        self.classifier = sa_classifier.StreamClassifier(config)

    def _prepare_and_classify_payload(self, service, entity, raw_record):
        """Helper method to return a preparsed and classified payload"""
        payload = load_stream_payload(service, entity, raw_record)

        payload = list(payload.pre_parse())[0]
        self.classifier.load_sources(service, entity)
        self.classifier.classify_record(payload)

        return payload

    def test_convert_type_string(self):
        """StreamClassifier - Convert Type, Default String"""
        payload = {'key_01': 10.101}
        schema = {'key_01': 'string'}

        self.classifier._convert_type(payload, schema)

        assert_is_instance(payload['key_01'], str)
        assert_equal(payload['key_01'], '10.101')

    def test_convert_type_valid_int(self):
        """StreamClassifier - Convert Type, Valid Int"""
        payload = {'key_01': '100'}
        schema = {'key_01': 'integer'}

        self.classifier._convert_type(payload, schema)

        assert_is_instance(payload['key_01'], int)

    @patch('logging.Logger.error')
    def test_convert_type_invalid_int(self, log_mock):
        """StreamClassifier - Convert Type, Invalid Int"""
        payload = {'key_01': 'NotInt'}
        schema = {'key_01': 'integer'}

        self.classifier._convert_type(payload, schema)

        log_mock.assert_called_with(
            'Invalid schema. Value for key [%s] is not an int: %s',
            'key_01',
            'NotInt')

    @patch('logging.Logger.error')
    def test_convert_type_invalid_nested(self, log_mock):
        """StreamClassifier - Convert Type, Invalid Nested Type"""
        payload = {'key_01': '100', 'streamalert:envelope_keys': {'host': 'NotInt'}}
        schema = {'key_01': 'integer', 'streamalert:envelope_keys': {'host': 'integer'}}

        assert_false(self.classifier._convert_type(payload, schema))

        log_mock.assert_called_with(
            'Invalid schema. Value for key [%s] is not an int: %s',
            'host',
            'NotInt')

    def test_convert_type_valid_float(self):
        """StreamClassifier - Convert Type, Valid Float"""
        payload = {'key_01': '12.1'}
        schema = {'key_01': 'float'}

        self.classifier._convert_type(payload, schema)

        assert_is_instance(payload['key_01'], float)

    @patch('logging.Logger.error')
    def test_convert_type_invalid_float(self, log_mock):
        """StreamClassifier - Convert Type, Invalid Float"""
        payload = {'key_01': 'NotFloat'}
        schema = {'key_01': 'float'}

        self.classifier._convert_type(payload, schema)

        log_mock.assert_called_with(
            'Invalid schema. Value for key [%s] is not a float: %s',
            'key_01',
            'NotFloat')

    @patch('logging.Logger.error')
    def test_convert_type_unsup_type(self, log_mock):
        """StreamClassifier - Convert Type, Unsupported Type"""
        payload = {'key_01': 'true'}
        schema = {'key_01': 'boopean'}

        self.classifier._convert_type(payload, schema)

        log_mock.assert_called_with('Unsupported schema type: %s', 'boopean')

    def test_convert_type_list(self):
        """StreamClassifier - Convert Type, Skip List"""
        payload = {'key_01': ['hi', '100']}
        schema = {'key_01': ['integer']}

        self.classifier._convert_type(payload, schema)

        # Make sure the list was not modified
        assert_list_equal(payload['key_01'], ['hi', '100'])

    def test_convert_type_type_error(self):
        """StreamClassifier - Convert Incompatible Types

        This is a bug where a list/dict tries to be casted
        as an int/float
        """
        payload = {'key': ['hi', '100']}
        schema = {'key': 'integer'}

        payload_2 = {'key': {'hi': '100'}}
        schema_2 = {'key': 'float'}

        results = []
        results.append(self.classifier._convert_type(payload, schema))
        results.append(self.classifier._convert_type(payload_2, schema_2))

        assert_false(all(results))

    def test_convert_recursion(self):
        """StreamClassifier - Convert Type, Recursive"""
        payload = {'key_01': {'nested_key_01': '20.1'}}
        schema = {'key_01': {'nested_key_01': 'float'}}

        self.classifier._convert_type(payload, schema)

        # Make sure the list was not modified
        assert_is_instance(payload['key_01']['nested_key_01'], float)

    def test_convert_cast_envelope(self):
        """StreamClassifier - Convert Type, Cast Envelope"""
        payload = {'key_01': '100', 'streamalert:envelope_keys': {'env': '200'}}
        schema = {'key_01': 'integer', 'streamalert:envelope_keys': {'env': 'integer'}}

        self.classifier._convert_type(payload, schema)

        # Make sure the list was not modified
        assert_is_instance(payload['streamalert:envelope_keys']['env'], int)

    def test_convert_skip_bad_envelope(self):
        """StreamClassifier - Convert Type, Skip Bad Envelope"""
        payload = {'key_01': '100', 'streamalert:envelope_keys': 'bad_value'}
        schema = {'key_01': 'integer', 'streamalert:envelope_keys': {'env': 'integer'}}

        self.classifier._convert_type(payload, schema)

        # Make sure the list was not modified
        assert_equal(payload['streamalert:envelope_keys'], 'bad_value')

    def test_service_entity_ext_kinesis(self):
        """StreamClassifier - Extract Service and Entity, Kinesis"""
        raw_record = {
            'kinesis': {
                'data': 'SGVsbG8sIHRoaXMgaXMgYSB0ZXN0IDEyMy4='
            },
            'eventSourceARN': 'arn:aws:kinesis:EXAMPLE/unit_test_stream_name'
        }

        service, entity = self.classifier.extract_service_and_entity(raw_record)

        assert_equal(service, 'kinesis')
        assert_equal(entity, 'unit_test_stream_name')

    def test_service_entity_ext_s3(self):
        """StreamClassifier - Extract Service and Entity, S3"""
        raw_record = {
            's3': {'bucket': {'name': 'unit_test_bucket'}}
        }

        service, entity = self.classifier.extract_service_and_entity(raw_record)

        assert_equal(service, 's3')
        assert_equal(entity, 'unit_test_bucket')

    def test_service_entity_ext_sns(self):
        """StreamClassifier - Extract Service and Entity, SNS"""
        raw_record = {
            'Sns': {'Message': 'test_message'},
            'EventSubscriptionArn': 'arn:aws:sns:us-east-1:123456789012:unit_test_topic'
        }

        service, entity = self.classifier.extract_service_and_entity(raw_record)

        assert_equal(service, 'sns')
        assert_equal(entity, 'unit_test_topic')

    def test_load_sources_valid(self):
        """StreamClassifier - Load Log Sources for Service and Entity, Valid"""
        service, entity = 'kinesis', 'unit_test_default_stream'

        result = self.classifier.load_sources(service, entity)

        assert_true(result)

        assert_equal(self.classifier._entity_log_sources[0], 'unit_test_simple_log')

    @patch('logging.Logger.error')
    def test_load_sources_invalid_serv(self, log_mock):
        """StreamClassifier - Load Log Sources for Service and Entity, Invalid Service"""
        service = 'kinesys'

        result = self.classifier.load_sources(service, '')

        assert_false(result)

        log_mock.assert_called_with('Service [%s] not declared in sources configuration',
                                    service)

    @patch('logging.Logger.error')
    def test_load_sources_invalid_ent(self, log_mock):
        """StreamClassifier - Load Log Sources for Service and Entity, Invalid Entity"""
        service, entity = 'kinesis', 'unit_test_bad_stream'

        result = self.classifier.load_sources(service, entity)

        assert_false(result)

        log_mock.assert_called_with(
            'Entity [%s] not declared in sources configuration for service [%s]',
            entity,
            service
        )

    def test_get_log_info(self):
        """StreamClassifier - Load Log Info for Source"""
        self.classifier._entity_log_sources.append('unit_test_simple_log')

        logs = self.classifier.get_log_info_for_source()

        assert_list_equal(logs.keys(), ['unit_test_simple_log'])

    @patch('logging.Logger.error')
    def test_parse_convert_fail(self, log_mock):
        """StreamClassifier - Convert Failed"""
        service, entity = 'kinesis', 'unit_test_default_stream'

        result = self.classifier.load_sources(service, entity)

        assert_true(result)

        kinesis_data = json.dumps({
            'unit_key_01': 'not an integer',
            'unit_key_02': 'valid string'
        })

        raw_record = make_kinesis_raw_record(entity, kinesis_data)
        payload = load_stream_payload(service, entity, raw_record)
        payload = list(payload.pre_parse())[0]

        result = self.classifier._parse(payload)

        assert_false(result)

        log_mock.assert_called_with(
            'Invalid schema. Value for key [%s] is not an int: %s',
            'unit_key_01', 'not an integer'
        )

    def test_mult_schema_match_success(self):
        """StreamClassifier - Multiple Schema Matching with Log Patterns, Success"""
        kinesis_data = json.dumps({
            'name': 'file added test',
            'identifier': 'host4.this.test',
            'time': 'Jan 01 2017',
            'type': 'lol_file_added_event_test',
            'message': 'bad_001.txt was added'
        })
        # Make sure support for multiple schema matching is ON
        sa_classifier.SUPPORT_MULTIPLE_SCHEMA_MATCHING = True

        service, entity = 'kinesis', 'test_stream_2'
        raw_record = make_kinesis_raw_record(entity, kinesis_data)
        payload = load_stream_payload(service, entity, raw_record)

        self.classifier.load_sources(service, entity)

        payload = list(payload.pre_parse())[0]

        schema_matches = self.classifier._process_log_schemas(payload)

        assert_equal(len(schema_matches), 2)
        assert_equal(schema_matches[0].log_name, 'test_multiple_schemas:01')
        assert_equal(schema_matches[1].log_name, 'test_multiple_schemas:02')
        schema_match = self.classifier._check_schema_match(schema_matches)

        assert_equal(schema_match.log_name, 'test_multiple_schemas:01')

    @patch('logging.Logger.error')
    def test_mult_schema_match_failure(self, log_mock):
        """StreamClassifier - Multiple Schema Matching with Log Patterns, Fail"""
        kinesis_data = json.dumps({
            'name': 'file removal test',
            'identifier': 'host4.this.test.also',
            'time': 'Jan 01 2017',
            'type': 'file_removed_event_test_file_added_event',
            'message': 'bad_001.txt was removed'
        })
        sa_classifier.SUPPORT_MULTIPLE_SCHEMA_MATCHING = True

        service, entity = 'kinesis', 'test_stream_2'
        raw_record = make_kinesis_raw_record(entity, kinesis_data)
        payload = load_stream_payload(service, entity, raw_record)

        self.classifier.load_sources(service, entity)

        payload = list(payload.pre_parse())[0]

        schema_matches = self.classifier._process_log_schemas(payload)

        assert_equal(len(schema_matches), 2)
        self.classifier._check_schema_match(schema_matches)

        log_mock.assert_called_with(
            'Proceeding with schema for: %s', 'test_multiple_schemas:01'
        )

    @patch('logging.Logger.error')
    def test_mult_schema_match(self, log_mock):
        """StreamClassifier - Multiple Schema Matching with Log Patterns"""
        kinesis_data = json.dumps({
            'name': 'file removal test',
            'identifier': 'host4.this.test.also',
            'time': 'Jan 01 2017',
            'type': 'random',
            'message': 'bad_001.txt was removed'
        })
        sa_classifier.SUPPORT_MULTIPLE_SCHEMA_MATCHING = True

        service, entity = 'kinesis', 'test_stream_2'
        raw_record = make_kinesis_raw_record(entity, kinesis_data)
        payload = load_stream_payload(service, entity, raw_record)

        self.classifier.load_sources(service, entity)

        payload = list(payload.pre_parse())[0]

        schema_matches = self.classifier._process_log_schemas(payload)

        assert_equal(len(schema_matches), 2)
        self.classifier._check_schema_match(schema_matches)

        calls = [call('Log classification matched for multiple schemas: %s',
                      'test_multiple_schemas:01, test_multiple_schemas:02'),
                 call('Proceeding with schema for: %s', 'test_multiple_schemas:01')]

        log_mock.assert_has_calls(calls)

    def test_classify_json_optional(self):
        """StreamClassifier - Classify JSON with optional fields"""
        kinesis_data = json.dumps({
            'key1': [
                {
                    'test': 1,
                    'test2': 2
                },
                {
                    'test3': 3,
                    'test4': 4
                }
            ],
            'key2': 'more sample data',
            'key3': '1',
            'key10': {
                'test-field': 1,
                'test-field2': 2
            }
        })

        service, entity = 'kinesis', 'test_kinesis_stream'
        raw_record = make_kinesis_raw_record(entity, kinesis_data)
        payload = self._prepare_and_classify_payload(service, entity, raw_record)

        # valid record test
        assert_equal(payload.valid, True)
        assert_is_instance(payload.records[0], dict)

        # log type test
        assert_equal(payload.log_source, 'test_log_type_json')

        # payload type test
        assert_equal(payload.type, 'json')

        # record value tests
        assert_equal(len(payload.records[0]['key1']), 2)
        assert_equal(payload.records[0]['key3'], 1)
        assert_equal(payload.records[0]['key1'][1]['test4'], 4)

        # optional field tests
        assert_equal(payload.records[0]['key11'], 0.0)
        assert_equal(payload.records[0]['key9'], False)
        assert_equal(len(payload.records[0]['key10']), 2)

        # record type tests
        assert_is_instance(payload.records[0]['key1'], list)
        assert_is_instance(payload.records[0]['key2'], str)
        assert_is_instance(payload.records[0]['key3'], int)

    def test_json_type_casting(self):
        """StreamClassifier - JSON with various types (boolean, float, integer)"""
        kinesis_data = json.dumps({
            'key4': 'true',
            'key5': '10.001',
            'key6': '10',
            'key7': False
        })

        service, entity = 'kinesis', 'test_kinesis_stream'
        raw_record = make_kinesis_raw_record(entity, kinesis_data)
        payload = self._prepare_and_classify_payload(service, entity, raw_record)

        # valid record test
        assert_equal(payload.valid, True)
        assert_is_instance(payload.records[0], dict)

        # log type test
        assert_equal(payload.log_source, 'test_log_type_json_2')

        # payload type test
        assert_equal(payload.type, 'json')

        # Check the types
        assert_is_instance(payload.records[0]['key4'], bool)
        assert_is_instance(payload.records[0]['key5'], float)
        assert_is_instance(payload.records[0]['key6'], int)
        assert_is_instance(payload.records[0]['key7'], bool)

    def test_classify_nested_json(self):
        """StreamClassifier - Classify Nested JSON"""
        kinesis_data = json.dumps({
            'date': 'Jan 01 2017',
            'unixtime': '1485556524',
            'host': 'my-host-name',
            'data': {
                'key1': 'test',
                'key2': 'one'
            }
        })

        service, entity = 'kinesis', 'test_kinesis_stream'
        raw_record = make_kinesis_raw_record(entity, kinesis_data)
        payload = self._prepare_and_classify_payload(service, entity, raw_record)

        # valid record test
        assert_equal(payload.valid, True)
        assert_is_instance(payload.records[0], dict)

        # log type test
        assert_equal(payload.log_source, 'test_log_type_json_nested')

        # payload type test
        assert_equal(payload.type, 'json')

        # record type test
        assert_is_instance(payload.records[0]['date'], str)
        assert_is_instance(payload.records[0]['unixtime'], int)
        assert_is_instance(payload.records[0]['data'], dict)

        # record value test
        assert_equal(payload.records[0]['date'], 'Jan 01 2017')
        assert_equal(payload.records[0]['data']['key1'], 'test')

    def test_csv(self):
        """StreamClassifier - Classify CSV"""
        csv_data = 'jan102017,0100,host1,thisis some data with keyword1 in it'

        service, entity = 'kinesis', 'test_kinesis_stream'
        raw_record = make_kinesis_raw_record(entity, csv_data)
        payload = self._prepare_and_classify_payload(service, entity, raw_record)

        # valid record test
        assert_equal(payload.valid, True)
        assert_is_instance(payload.records[0], dict)

        # record value tests
        assert_equal(payload.records[0]['message'],
                     'thisis some data with keyword1 in it')
        assert_equal(payload.records[0]['host'], 'host1')

        # type test
        assert_equal(payload.type, 'csv')

        # log source test
        assert_equal(payload.log_source, 'test_log_type_csv')

    def test_csv_nested(self):
        """StreamClassifier - Classify Nested CSV"""
        csv_nested_data = (
            '"Jan 10 2017","1485635414","host1.prod.test","Corp",'
            '"chef,web-server,1,10,success"'
        )

        service, entity = 'kinesis', 'test_kinesis_stream'
        raw_record = make_kinesis_raw_record(entity, csv_nested_data)
        payload = self._prepare_and_classify_payload(service, entity, raw_record)

        # valid record test
        assert_equal(payload.valid, True)
        assert_is_instance(payload.records[0], dict)

        # record value tests
        assert_equal(payload.records[0]['date'], 'Jan 10 2017')
        assert_equal(payload.records[0]['host'], 'host1.prod.test')
        assert_equal(payload.records[0]['time'], 1485635414)
        assert_equal(payload.records[0]['message']['role'], 'web-server')
        assert_equal(payload.records[0]['message']['cluster_size'], 10)

        # type test
        assert_equal(payload.type, 'csv')

        # log source test
        assert_equal(payload.log_source, 'test_log_type_csv_nested')

    def test_classify_kv(self):
        """StreamClassifier - Classify Key/Value"""
        auditd_test_data = (
            'type=SYSCALL msg=audit(1364481363.243:24287): '
            'arch=c000003e syscall=2 success=no exit=-13 a0=7fffd19c5592 a1=0 '
            'a2=7fffd19c4b50 a3=a items=1 ppid=2686 pid=3538 auid=500 uid=500 '
            'gid=500 euid=500 suid=500 fsuid=500 egid=500 sgid=500 fsgid=500 tty=pts0 '
            'ses=1 comm="cat" exe="/bin/cat" '
            'subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 '
            'key="sshd_config" type=CWD msg=audit(1364481363.243:24287):  '
            'cwd="/home/shadowman" type=PATH '
            'msg=audit(1364481363.243:24287): item=0 name="/etc/ssh/sshd_config" '
            'inode=409248 dev=fd:00 mode=0100600 ouid=0 ogid=0 '
            'rdev=00:00 obj=system_u:object_r:etc_t:s0'
        )

        service, entity = 'kinesis', 'test_kinesis_stream'
        raw_record = make_kinesis_raw_record(entity, auditd_test_data)
        payload = self._prepare_and_classify_payload(service, entity, raw_record)

        # valid record test
        assert_equal(payload.valid, True)
        assert_is_instance(payload.records[0], dict)

        # record value tests
        assert_equal(payload.records[0]['type'], 'SYSCALL')
        assert_equal(payload.records[0]['suid'], 500)
        assert_equal(payload.records[0]['pid'], 3538)
        assert_equal(payload.records[0]['type_3'], 'PATH')

        # type test
        assert_equal(payload.type, 'kv')

    def test_classify_syslog(self):
        """StreamClassifier - Classify syslog"""
        test_data_1 = (
            'Jan 26 19:35:33 vagrant-ubuntu-trusty-64 '
            'sudo: pam_unix(sudo:session): '
            'session opened for user root by (uid=0)'
        )
        test_data_2 = (
            "Jan 26 12:28:06 macbook004154test authd[122]: "
            "Succeeded authorizing right 'com.apple.trust-settings.admin' "
            "by client '/usr/sbin/ocspd' [11835] for authorization created by"
            " '/usr/bin/security' [21322] (3,0)"
        )

        fixtures = {'test_1': test_data_1, 'test_2': test_data_2}
        for name, syslog_message in fixtures.iteritems():

            service, entity = 'kinesis', 'test_stream_2'
            raw_record = make_kinesis_raw_record(entity, syslog_message)
            payload = self._prepare_and_classify_payload(service, entity, raw_record)

            # valid record test
            assert_equal(payload.valid, True)
            assert_is_instance(payload.records[0], dict)

            # type test
            assert_equal(payload.type, 'syslog')

            # record value tests
            if name == 'test_1':
                assert_equal(payload.records[0]['host'], 'vagrant-ubuntu-trusty-64')
                assert_equal(payload.records[0]['application'], 'sudo')
                assert_equal(payload.records[0]['message'], 'pam_unix(sudo:session):'
                                                            ' session opened for user'
                                                            ' root by (uid=0)')
            elif name == 'test_2':
                assert_equal(payload.records[0]['host'], 'macbook004154test')
                assert_equal(payload.records[0]['application'], 'authd')
