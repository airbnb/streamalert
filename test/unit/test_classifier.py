'''
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
'''

# command: nosetests -v -s test/unit/
# specific test: nosetests -v -s test/unit/file.py:TestStreamPayload.test_name

import base64
import json

from collections import OrderedDict

from nose.tools import assert_equal, assert_not_equal, nottest

from stream_alert.classifier import StreamPayload, StreamPayloadHelpers
from stream_alert.config import load_config

class TestStreamPayload(object):
    @classmethod
    def setup_class(cls):
        """setup_class() before any methods in this class"""
        pass

    @classmethod
    def teardown_class(cls):
        """teardown_class() after any methods in this class"""
        pass

    @staticmethod
    def pre_parse_kinesis(payload):
        return StreamPayloadHelpers.pre_parse_kinesis(payload.raw_record)

    @staticmethod
    def make_kinesis_record(**kwargs):
        kinesis_stream = kwargs.get('kinesis_stream')
        kinesis_data = kwargs.get('kinesis_data')
        raw_record = {
            'eventSource': 'aws:kinesis',
            'eventSourceARN': 'arn:aws:kinesis:us-east-1:123456789012:stream/{}'
                .format(kinesis_stream),
            'kinesis': {
                'data': base64.b64encode(kinesis_data)
            }
        }
        return raw_record

    def setup(self):
        """Setup before each method"""
        self.env = {
            'lambda_region': 'us-east-1',
            'account_id': '123456789012',
            'lambda_function_name': 'test_kinesis_stream',
            'lambda_alias': 'production'
        }
        self.config = load_config('test/unit/conf')
        self.log_metadata = self.config['logs']

    def teardown(self):
        """Teardown after each method"""
        pass

    def test_refresh_record(self):
        kinesis_data = {
            'key3': 'key3data',
            'key2': 'key2data',
            'key1': 'key1data'
        }
        kinesis_data_json = json.dumps(kinesis_data)
        first_raw_record = self.make_kinesis_record(kinesis_stream='test_kinesis_stream',
                                               kinesis_data=kinesis_data_json)
        payload = StreamPayload(raw_record=first_raw_record,
                                env=self.env,
                                config=self.config)

        # generate a second record
        new_kinesis_data = {
            'key4': 'key4data',
            'key5': 'key5data',
            'key6': 'key6data'
        }
        new_kinesis_data_json = json.dumps(new_kinesis_data)
        second_record = self.make_kinesis_record(kinesis_stream='test_kinesis_stream',
                                               kinesis_data=new_kinesis_data_json)
        payload.refresh_record(second_record)

        # check loaded record
        assert_equal(payload.raw_record, second_record)
        assert_not_equal(payload.raw_record, first_raw_record)

    def test_map_source(self):
        data = 'test_map_source data'
        data_encoded = base64.b64encode(data)
        raw_record = self.make_kinesis_record(kinesis_stream='test_kinesis_stream',
                                               kinesis_data=data_encoded)

        payload = StreamPayload(raw_record=raw_record,
                                env=self.env,
                                config=self.config)
        payload.map_source()

        test_kinesis_stream_logs = {
            'test_log_type_json',
            'test_log_type_json_2',
            'test_log_type_json_nested',
            'test_log_type_json_nested_with_data',
            'test_log_type_csv',
            'test_log_type_csv_nested',
            'test_log_type_kv_auditd',
            'test_log_type_syslog'
        }
        
        # service, entity, metadata test
        assert_equal(payload.service, 'kinesis')
        assert_equal(payload.entity, 'test_kinesis_stream')
        assert_equal(set(payload.log_metadata.keys()), test_kinesis_stream_logs)

        # second stream test
        raw_record_2 = self.make_kinesis_record(kinesis_stream='test_stream_2',
                                               kinesis_data=data_encoded)

        payload_2 = StreamPayload(raw_record=raw_record_2,
                                env=self.env,
                                config=self.config)
        payload_2.map_source()

        test_stream_2_logs = {
            'test_log_type_json_2',
            'test_log_type_json_nested_osquery'
        }

        # service, entity, metadata test
        assert_equal(payload_2.service, 'kinesis')
        assert_equal(payload_2.entity, 'test_stream_2')
        assert_equal(set(payload_2.log_metadata.keys()), test_stream_2_logs)

    def test_classify_record_kinesis_json(self):
        kinesis_data = {
            'key1': 'sample data!!!!',
            'key2': 'more sample data',
            'key3': '1'
        }
        kinesis_data_json = json.dumps(kinesis_data)
        raw_record = self.make_kinesis_record(kinesis_stream='test_kinesis_stream',
                                               kinesis_data=kinesis_data_json)

        payload = StreamPayload(raw_record=raw_record,
                                env=self.env,
                                config=self.config)
        payload.map_source()

        data = self.pre_parse_kinesis(payload)
        payload.classify_record(data)

        # valid record test
        assert_equal(payload.valid, True)
        assert_equal(type(payload.record), dict)

        # log type test
        assert_equal(payload.log_source, 'test_log_type_json')

        # payload type test
        assert_equal(payload.type, 'json')
        assert_not_equal(payload.type, 'csv')

        # record type test
        assert_equal(type(payload.record['key1']), str)
        assert_equal(type(payload.record['key2']), str)
        assert_equal(type(payload.record['key3']), int)

    def test_classify_record_kinesis_nested_json(self):
        kinesis_data = {
            'date': 'Jan 01 2017',
            'unixtime': '1485556524',
            'host': 'my-host-name',
            'data': {
                'key1': 'test',
                'key2': 'one'
            }
        }
        kinesis_data_json = json.dumps(kinesis_data)
        raw_record = self.make_kinesis_record(kinesis_stream='test_kinesis_stream',
                                               kinesis_data=kinesis_data_json)

        payload = StreamPayload(raw_record=raw_record,
                                env=self.env,
                                config=self.config)
        payload.map_source()

        data = self.pre_parse_kinesis(payload)
        payload.classify_record(data)

        # valid record test
        assert_equal(payload.valid, True)
        assert_equal(type(payload.record), dict)

        # log type test
        assert_equal(payload.log_source, 'test_log_type_json_nested')

        # payload type test
        assert_equal(payload.type, 'json')
        assert_not_equal(payload.type, 'csv')

        # record type test
        assert_equal(type(payload.record['date']), str)
        assert_equal(type(payload.record['unixtime']), int)
        assert_equal(type(payload.record['data']), dict)

        # record value test
        assert_equal(payload.record['date'], 'Jan 01 2017')
        assert_equal(payload.record['data']['key1'], 'test')

    def test_classify_record_kinesis_nested_json_osquery(self):
        kinesis_data = {
            'name': 'testquery',
            'hostIdentifier': 'host1.test.prod',
            'calendarTime': 'Jan 01 2017',
            'unixTime': '1485556524',
            'columns': {
                'key1': 'test',
                'key2': 'one'
            },
            'action': 'added',
            'decorations': {
                'role': 'web-server',
                'env': 'production',
                'cluster': 'eu-east',
                'number': '100'
            }
        }
        kinesis_data_json = json.dumps(kinesis_data)
        raw_record = self.make_kinesis_record(kinesis_stream='test_stream_2',
                                               kinesis_data=kinesis_data_json)

        payload = StreamPayload(raw_record=raw_record,
                                env=self.env,
                                config=self.config)
        payload.map_source()

        data = self.pre_parse_kinesis(payload)
        payload.classify_record(data)

        # valid record test
        assert_equal(payload.valid, True)
        assert_equal(type(payload.record), dict)

        # log type test
        assert_equal(payload.log_source, 'test_log_type_json_nested_osquery')

        # payload type test
        assert_equal(payload.type, 'json')
        assert_not_equal(payload.type, 'csv')

        # record type test
        assert_equal(type(payload.record['hostIdentifier']), str)
        assert_equal(type(payload.record['unixTime']), int)
        assert_equal(type(payload.record['columns']), dict)
        assert_equal(type(payload.record['decorations']), dict)

        # record value test
        assert_equal(payload.record['unixTime'], 1485556524)
        assert_equal(payload.record['columns']['key1'], 'test')
        assert_equal(payload.record['decorations']['cluster'], 'eu-east')
        assert_equal(payload.record['decorations']['number'], 100)

    def test_classify_record_kinesis_nested_json_missing_subkey_fields(self):
        kinesis_data = {
            'name': 'testquery',
            'hostIdentifier': 'host1.test.prod',
            'calendarTime': 'Jan 01 2017',
            'unixTime': '12321412321',
            'columns': {
                'key1': 'test',
                'key2': 'one'
            },
            'action': 'added',
            'decorations': {
                'role': 'web-server',
                'env': 'production',
                # 'cluster': 'eu-east',
                'number': '100'
            }
        }
        kinesis_data_json = json.dumps(kinesis_data)
        raw_record = self.make_kinesis_record(kinesis_stream='test_stream_2',
                                               kinesis_data=kinesis_data_json)

        payload = StreamPayload(raw_record=raw_record,
                                env=self.env,
                                config=self.config)
        payload.map_source()

        data = self.pre_parse_kinesis(payload)
        payload.classify_record(data)

        # invalid record test
        assert_equal(payload.valid, False)
        assert_equal(payload.record, None)

    def test_classify_record_kinesis_nested_json_with_data(self):
        kinesis_data = {
            'date': 'Jan 01 2017',
            'unixtime': '1485556524',
            'host': 'host1',
            'application': 'myapp',
            'environment': 'development',
            'data': {
                'category': 'test',
                'type': '1',
                'source': 'dev-app-1'
            }
        }
        kinesis_data_json = json.dumps(kinesis_data)
        raw_record = self.make_kinesis_record(kinesis_stream='test_kinesis_stream',
                                               kinesis_data=kinesis_data_json)

        payload = StreamPayload(raw_record=raw_record,
                                env=self.env,
                                config=self.config)
        payload.map_source()

        data = self.pre_parse_kinesis(payload)
        payload.classify_record(data)

        # valid record test
        assert_equal(payload.valid, True)
        assert_equal(type(payload.record), dict)
        
        # log type test
        assert_equal(payload.log_source, 'test_log_type_json_nested_with_data')

        # payload type test
        assert_equal(payload.type, 'json')
        assert_not_equal(payload.type, 'csv')

        # record type test
        assert_equal(type(payload.record['date']), str)
        assert_equal(type(payload.record['unixtime']), int)
        assert_equal(type(payload.record['data']), dict)
        assert_equal(type(payload.record['data']['type']), int)
        assert_equal(type(payload.record['data']['category']), str)

        # record value test
        assert_equal(payload.record['date'], 'Jan 01 2017')
        assert_equal(payload.record['data']['source'], 'dev-app-1')

    def test_classify_record_kinesis_csv(self):
        csv_data = 'jan102017,0100,host1,thisis some data with keyword1 in it'
        raw_record = self.make_kinesis_record(kinesis_stream='test_kinesis_stream',
                                               kinesis_data=csv_data)
        payload = StreamPayload(raw_record=raw_record,
                                env=self.env,
                                config=self.config)
        payload.map_source()
        data = self.pre_parse_kinesis(payload)
        payload.classify_record(data)

        # valid record test
        assert_equal(payload.valid, True)
        assert_equal(type(payload.record), dict)

        # record value tests
        assert_equal(payload.record.get('message'), 'thisis some data with keyword1 in it')
        assert_equal(payload.record.get('host'), 'host1')

        # type test
        assert_equal(payload.type, 'csv')
        assert_not_equal(payload.type, 'json')

        # log source test
        assert_equal(payload.log_source, 'test_log_type_csv')

    def test_classify_record_kinesis_csv_nested(self):
        csv_nested_data = (
            '"Jan 10 2017","1485635414","host1.prod.test","Corp",'
            '"chef,web-server,1,10,success"'
        )
        raw_record = self.make_kinesis_record(kinesis_stream='test_kinesis_stream',
                                               kinesis_data=csv_nested_data)
        payload = StreamPayload(raw_record=raw_record,
                                env=self.env,
                                config=self.config)
        payload.map_source()
        data = self.pre_parse_kinesis(payload)
        payload.classify_record(data)

        # valid record test
        assert_equal(payload.valid, True)
        assert_equal(type(payload.record), dict)

        # record value tests
        assert_equal(payload.record['date'], 'Jan 10 2017')
        assert_equal(payload.record['host'], 'host1.prod.test')
        assert_equal(payload.record['time'], 1485635414)
        assert_equal(payload.record['message']['role'], 'web-server')
        assert_equal(payload.record['message']['cluster_size'], 10)

        # type test
        assert_equal(payload.type, 'csv')
        assert_not_equal(payload.type, 'json')

        # log source test
        assert_equal(payload.log_source, 'test_log_type_csv_nested')

    def test_classify_record_kinesis_kv(self):
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

        raw_record = self.make_kinesis_record(kinesis_stream='test_kinesis_stream',
                                               kinesis_data=auditd_test_data)
        payload = StreamPayload(raw_record=raw_record,
                                env=self.env,
                                config=self.config)
        payload.map_source()
        data = self.pre_parse_kinesis(payload)
        payload.classify_record(data)

        # valid record test
        assert_equal(payload.valid, True)
        assert_equal(type(payload.record), dict)

        # record value tests
        assert_equal(payload.record.get('type'), 'SYSCALL')
        assert_equal(payload.record.get('suid'), 500)
        assert_equal(payload.record.get('pid'), 3538)
        assert_equal(payload.record.get('type_3'), 'PATH')

        # type test
        assert_equal(payload.type, 'kv')
        assert_not_equal(payload.type, 'csv')
        assert_not_equal(payload.type, 'json')

    def test_classify_record_syslog(self):
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
            raw_record = self.make_kinesis_record(kinesis_stream='test_kinesis_stream',
                                                   kinesis_data=syslog_message)
            payload = StreamPayload(raw_record=raw_record,
                                    env=self.env,
                                    config=self.config)
            payload.map_source()
            data = self.pre_parse_kinesis(payload)
            payload.classify_record(data)

            # valid record test
            assert_equal(payload.valid, True)
            assert_equal(type(payload.record), dict)

            # type test
            assert_equal(payload.type, 'syslog')
            assert_not_equal(payload.type, 'csv')
            assert_not_equal(payload.type, 'json')
            assert_not_equal(payload.type, 'kv')

            # record value tests
            if name == 'test_1':
                assert_equal(payload.record.get('host'), 'vagrant-ubuntu-trusty-64')
                assert_equal(payload.record.get('application'), 'sudo')
                assert_equal(payload.record.get('message'), 'pam_unix(sudo:session): session opened for user root by (uid=0)')
            elif name == 'test_2':
                assert_equal(payload.record.get('host'), 'macbook004154test')
                assert_equal(payload.record.get('application'), 'authd')
