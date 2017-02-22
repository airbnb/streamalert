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

from stream_alert.classifier import StreamPayload, StreamClassifier
from stream_alert.pre_parsers import StreamPreParsers
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
        return StreamPreParsers.pre_parse_kinesis(payload.raw_record)

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

    def payload_generator(self, **kwargs):
        """Given raw data, return a payload object"""
        kinesis_stream = kwargs['kinesis_stream']
        kinesis_data = kwargs['kinesis_data']
        kinesis_record = self.make_kinesis_record(kinesis_stream=kinesis_stream,
                                                  kinesis_data=kinesis_data)
        
        payload = StreamPayload(raw_record=kinesis_record)
        return payload

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
        kinesis_data = json.dumps({
            'key3': 'key3data',
            'key2': 'key2data',
            'key1': 'key1data'
        })
        payload = self.payload_generator(kinesis_stream='test_kinesis_stream',
                                         kinesis_data=kinesis_data)

        # generate a second record
        new_kinesis_data = json.dumps({
            'key4': 'key4data',
            'key5': 'key5data',
            'key6': 'key6data'
        })
        second_record = self.make_kinesis_record(kinesis_stream='test_kinesis_stream',
                                 kinesis_data=new_kinesis_data)
        payload.refresh_record(second_record)

        # check newly loaded record
        assert_equal(payload.raw_record, second_record)


    def test_map_source_1(self):
        data_encoded = base64.b64encode('test_map_source data')
        payload = self.payload_generator(kinesis_stream='test_kinesis_stream',
                                         kinesis_data=data_encoded)

        classifier = StreamClassifier(config=self.config)
        classifier.map_source(payload)

        test_kinesis_stream_logs = {
            'test_log_type_json',
            'test_log_type_json_2',
            'test_log_type_json_nested',
            'test_log_type_json_nested_with_data',
            'test_log_type_csv',
            'test_log_type_csv_nested',
            'test_log_type_kv_auditd'
        }
        metadata = classifier.log_metadata(payload)

        # service, entity, metadata test
        assert_equal(payload.service, 'kinesis')
        assert_equal(payload.entity, 'test_kinesis_stream')
        assert_equal(set(metadata.keys()), test_kinesis_stream_logs)


    def test_map_source_2(self):
        data_encoded = base64.b64encode('test_map_source_data_2')
        payload = self.payload_generator(kinesis_stream='test_stream_2',
                                         kinesis_data=data_encoded)

        classifier = StreamClassifier(config=self.config)
        classifier.map_source(payload)

        test_stream_2_logs = {
            'test_log_type_json_2',
            'test_log_type_json_nested_osquery',
            'test_log_type_syslog'
        }
        metadata = classifier.log_metadata(payload)

        # service, entity, metadata test
        assert_equal(payload.service, 'kinesis')
        assert_equal(payload.entity, 'test_stream_2')
        assert_equal(set(metadata.keys()), test_stream_2_logs)


    def test_classify_record_kinesis_json(self):
        kinesis_data = json.dumps({
            'key1': 'sample data!!!!',
            'key2': 'more sample data',
            'key3': '1'
        })
        payload = self.payload_generator(kinesis_stream='test_kinesis_stream',
                                         kinesis_data=kinesis_data)
        classifier = StreamClassifier(config=self.config)
        classifier.map_source(payload)

        # pre parse and classify
        data = self.pre_parse_kinesis(payload)
        classifier.classify_record(payload, data)

        # valid record test
        assert_equal(payload.valid, True)
        assert_equal(type(payload.records[0]), dict)

        # log type test
        assert_equal(payload.log_source, 'test_log_type_json')

        # payload type test
        assert_equal(payload.type, 'json')
        assert_not_equal(payload.type, 'csv')

        # record type test
        assert_equal(type(payload.records[0]['key1']), str)
        assert_equal(type(payload.records[0]['key2']), str)
        assert_equal(type(payload.records[0]['key3']), int)


    def test_classify_record_kinesis_nested_json(self):
        kinesis_data = json.dumps({
            'date': 'Jan 01 2017',
            'unixtime': '1485556524',
            'host': 'my-host-name',
            'data': {
                'key1': 'test',
                'key2': 'one'
            }
        })
        payload = self.payload_generator(kinesis_stream='test_kinesis_stream',
                                         kinesis_data=kinesis_data)
        classifier = StreamClassifier(config=self.config)
        classifier.map_source(payload)

        data = self.pre_parse_kinesis(payload)
        classifier.classify_record(payload, data)

        # valid record test
        assert_equal(payload.valid, True)
        assert_equal(type(payload.records[0]), dict)

        # log type test
        assert_equal(payload.log_source, 'test_log_type_json_nested')

        # payload type test
        assert_equal(payload.type, 'json')
        assert_not_equal(payload.type, 'csv')

        # record type test
        assert_equal(type(payload.records[0]['date']), str)
        assert_equal(type(payload.records[0]['unixtime']), int)
        assert_equal(type(payload.records[0]['data']), dict)

        # record value test
        assert_equal(payload.records[0]['date'], 'Jan 01 2017')
        assert_equal(payload.records[0]['data']['key1'], 'test')


    def test_classify_record_kinesis_nested_json_osquery(self):
        kinesis_data = json.dumps({
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
        })
        payload = self.payload_generator(kinesis_stream='test_stream_2',
                                         kinesis_data=kinesis_data)

        classifier = StreamClassifier(config=self.config)
        classifier.map_source(payload)

        data = self.pre_parse_kinesis(payload)
        classifier.classify_record(payload, data)

        # valid record test
        assert_equal(payload.valid, True)
        assert_equal(type(payload.records[0]), dict)

        # log type test
        assert_equal(payload.log_source, 'test_log_type_json_nested_osquery')

        # payload type test
        assert_equal(payload.type, 'json')
        assert_not_equal(payload.type, 'csv')

        # record type test
        assert_equal(type(payload.records[0]['hostIdentifier']), str)
        assert_equal(type(payload.records[0]['unixTime']), int)
        assert_equal(type(payload.records[0]['columns']), dict)
        assert_equal(type(payload.records[0]['decorations']), dict)

        # record value test
        assert_equal(payload.records[0]['unixTime'], 1485556524)
        assert_equal(payload.records[0]['columns']['key1'], 'test')
        assert_equal(payload.records[0]['decorations']['cluster'], 'eu-east')
        assert_equal(payload.records[0]['decorations']['number'], 100)


    def test_classify_record_kinesis_nested_json_missing_subkey_fields(self):
        kinesis_data = json.dumps({
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
        })
        payload = self.payload_generator(kinesis_stream='test_stream_2',
                                               kinesis_data=kinesis_data)

        classifier = StreamClassifier(config=self.config)
        classifier.map_source(payload)

        data = self.pre_parse_kinesis(payload)
        classifier.classify_record(payload, data)

        # invalid record test
        assert_equal(payload.valid, False)
        assert_equal(payload.records, None)


    def test_classify_record_kinesis_nested_json_with_data(self):
        kinesis_data = json.dumps({
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
        })
        payload = self.payload_generator(kinesis_stream='test_kinesis_stream',
                                               kinesis_data=kinesis_data)

        classifier = StreamClassifier(config=self.config)
        classifier.map_source(payload)

        data = self.pre_parse_kinesis(payload)
        classifier.classify_record(payload, data)

        # valid record test
        assert_equal(payload.valid, True)
        assert_equal(type(payload.records[0]), dict)
        
        # log type test
        assert_equal(payload.log_source, 'test_log_type_json_nested_with_data')

        # payload type test
        assert_equal(payload.type, 'json')
        assert_not_equal(payload.type, 'csv')

        # record type test
        assert_equal(type(payload.records[0]['date']), str)
        assert_equal(type(payload.records[0]['unixtime']), int)
        assert_equal(type(payload.records[0]['data']), dict)
        assert_equal(type(payload.records[0]['data']['type']), int)
        assert_equal(type(payload.records[0]['data']['category']), str)

        # record value test
        assert_equal(payload.records[0]['date'], 'Jan 01 2017')
        assert_equal(payload.records[0]['data']['source'], 'dev-app-1')


    def test_classify_record_kinesis_csv(self):
        csv_data = 'jan102017,0100,host1,thisis some data with keyword1 in it'
        payload = self.payload_generator(kinesis_stream='test_kinesis_stream',
                                               kinesis_data=csv_data)

        classifier = StreamClassifier(config=self.config)
        classifier.map_source(payload)

        data = self.pre_parse_kinesis(payload)
        classifier.classify_record(payload, data)

        # valid record test
        assert_equal(payload.valid, True)
        assert_equal(type(payload.records[0]), dict)

        # record value tests
        assert_equal(payload.records[0]['message'],
                     'thisis some data with keyword1 in it')
        assert_equal(payload.records[0]['host'], 'host1')

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
        payload = self.payload_generator(kinesis_stream='test_kinesis_stream',
                                         kinesis_data=csv_nested_data)

        classifier = StreamClassifier(config=self.config)
        classifier.map_source(payload)

        data = self.pre_parse_kinesis(payload)
        classifier.classify_record(payload, data)

        # valid record test
        assert_equal(payload.valid, True)
        assert_equal(type(payload.records[0]), dict)

        # record value tests
        assert_equal(payload.records[0]['date'], 'Jan 10 2017')
        assert_equal(payload.records[0]['host'], 'host1.prod.test')
        assert_equal(payload.records[0]['time'], 1485635414)
        assert_equal(payload.records[0]['message']['role'], 'web-server')
        assert_equal(payload.records[0]['message']['cluster_size'], 10)

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

        payload = self.payload_generator(kinesis_stream='test_kinesis_stream',
                                         kinesis_data=auditd_test_data)

        classifier = StreamClassifier(config=self.config)
        classifier.map_source(payload)

        data = self.pre_parse_kinesis(payload)
        classifier.classify_record(payload, data)

        # valid record test
        assert_equal(payload.valid, True)
        assert_equal(type(payload.records[0]), dict)

        # record value tests
        assert_equal(payload.records[0]['type'], 'SYSCALL')
        assert_equal(payload.records[0]['suid'], 500)
        assert_equal(payload.records[0]['pid'], 3538)
        assert_equal(payload.records[0]['type_3'], 'PATH')

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
            payload = self.payload_generator(kinesis_stream='test_stream_2',
                                             kinesis_data=syslog_message)

            classifier = StreamClassifier(config=self.config)
            classifier.map_source(payload)

            data = self.pre_parse_kinesis(payload)
            classifier.classify_record(payload, data)

            # valid record test
            assert_equal(payload.valid, True)
            assert_equal(type(payload.records[0]), dict)

            # type test
            assert_equal(payload.type, 'syslog')
            assert_not_equal(payload.type, 'csv')
            assert_not_equal(payload.type, 'json')
            assert_not_equal(payload.type, 'kv')

            # record value tests
            if name == 'test_1':
                assert_equal(payload.records[0]['host'], 'vagrant-ubuntu-trusty-64')
                assert_equal(payload.records[0]['application'], 'sudo')
                assert_equal(payload.records[0]['message'], 'pam_unix(sudo:session): session opened for user root by (uid=0)')
            elif name == 'test_2':
                assert_equal(payload.records[0]['host'], 'macbook004154test')
                assert_equal(payload.records[0]['application'], 'authd')
