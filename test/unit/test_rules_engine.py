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

import base64
import json

from nose.tools import assert_equal, assert_not_equal, nottest

from stream_alert.classifier import StreamPayload, StreamClassifier
from stream_alert.pre_parsers import StreamPreParsers
from stream_alert.config import load_config
from stream_alert.rules_engine import StreamRules

rule = StreamRules.rule
matcher = StreamRules.matcher

class TestStreamRules(object):
    @classmethod
    def setup_class(cls):
        """setup_class() before any methods in this class"""
        pass

    @classmethod
    def teardown_class(cls):
        """teardown_class() after any methods in this class"""
        pass

    def setup(self):
        self.env = {
            'lambda_region': 'us-east-1',
            'account_id': '123456789012',
            'lambda_function_name': 'stream_alert_test',
            'lambda_alias': 'production'
        }
        self.config = load_config('test/unit/conf')
        self.log_metadata = self.config['logs']
        pass

    def teardown(self):
        pass

    @staticmethod
    def pre_parse_kinesis(payload):
        return StreamPreParsers.pre_parse_kinesis(payload.raw_record)

    def make_kinesis_payload(self, **kwargs):
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
        payload = StreamPayload(raw_record=raw_record)
        classifier = StreamClassifier(config=self.config)

        classifier.map_source(payload)
        data = self.pre_parse_kinesis(payload)
        classifier.classify_record(payload, data)

        if payload.valid:
            return payload

    def test_alert_format(self):
        @rule('alert_format_test',
              logs=['test_log_type_json_nested_with_data'],
              outputs=['s3'])
        def alert_format_test(rec):
            return rec['application'] == 'web-app'

        kinesis_data = {
            'date': 'Dec 01 2016',
            'unixtime': '1483139547',
            'host': 'host1.web.prod.net',
            'application': 'web-app',
            'environment': 'prod',
            'data': {
                'category': 'web-server',
                'type': '1',
                'source': 'eu'
            }
        }
        # prepare the payloads
        kinesis_data_json = json.dumps(kinesis_data)
        payload = self.make_kinesis_payload(kinesis_stream='test_kinesis_stream',
                                            kinesis_data=kinesis_data_json)

        # process payloads
        alerts = StreamRules.process(payload)

        alert_keys = {'rule_name', 'metadata', 'record'}
        metadata_keys = {'log', 'outputs', 'type', 'source'}
        assert_equal(set(alerts[0].keys()), alert_keys)
        assert_equal(set(alerts[0]['metadata'].keys()), metadata_keys)

        # test alert fields
        assert_equal(type(alerts[0]['rule_name']), str)
        assert_equal(type(alerts[0]['record']), dict)
        assert_equal(type(alerts[0]['metadata']['outputs']), list)
        assert_equal(type(alerts[0]['metadata']['type']), str)
        assert_equal(type(alerts[0]['metadata']['source']), dict)
        assert_equal(type(alerts[0]['metadata']['log']), str)


    def test_basic_rule_matcher_process(self):
        @matcher('prod')
        def prod(rec):
            return rec['environment'] == 'prod'

        @rule('incomplete_rule')
        def incomplete_rule(rec):
            return True

        @rule('minimal_rule',
              logs=['test_log_type_json_nested_with_data'],
              outputs=['s3'])
        def minimal_rule(rec):
            return rec['unixtime'] == 1483139547

        @rule('chef_logs',
              matchers=['foobar', 'prod'],
              logs=['test_log_type_json_nested_with_data'],
              outputs=['pagerduty'])
        def chef_logs(rec):
            return rec['application'] == 'chef'

        kinesis_data = {
            'date': 'Dec 01 2016',
            'unixtime': '1483139547',
            'host': 'host1.web.prod.net',
            'application': 'chef',
            'environment': 'prod',
            'data': {
                'category': 'web-server',
                'type': '1',
                'source': 'eu'
            }
        }
        # prepare the payloads
        kinesis_data_json = json.dumps(kinesis_data)
        payload = self.make_kinesis_payload(kinesis_stream='test_kinesis_stream',
                                            kinesis_data=kinesis_data_json)

        # process payloads
        alerts = StreamRules.process(payload)

        # check alert output
        assert_equal(len(alerts), 2)

        # alert 1 tests
        assert_equal(alerts[1]['rule_name'], 'chef_logs')
        assert_equal(alerts[1]['metadata']['outputs'], ['pagerduty'])

        # alert 0 tests
        assert_equal(alerts[0]['rule_name'], 'minimal_rule')
        assert_equal(alerts[0]['metadata']['outputs'], ['s3'])

    def test_process_req_subkeys(self):
        @rule('data_location',
              logs=['test_log_type_json_nested'],
              outputs=['s3'],
              req_subkeys={'data': ['location']})
        def data_location(rec):
            return rec['data']['location'].startswith('us')

        @rule('web_server',
              logs=['test_log_type_json_nested'],
              outputs=['s3'],
              req_subkeys={'data': ['category']})
        def web_server(rec):
            return rec['data']['category'] == 'web-server'

        kinesis_data = [
            {
                'date': 'Dec 01 2016',
                'unixtime': '1483139547',
                'host': 'host1.web.prod.net',
                'data': {
                    'category': 'web-server',
                    'type': '1',
                    'source': 'eu'
                }
            },
            {
                'date': 'Dec 01 2016',
                'unixtime': '1483139547',
                'host': 'host1.web.prod.net',
                'data': {
                    'location': 'us-west-2'
                }
            }
        ]
        # prepare payloads
        payloads = []
        for data in kinesis_data:
            kinesis_data_json = json.dumps(data)
            payload = self.make_kinesis_payload(kinesis_stream='test_kinesis_stream',
                                                kinesis_data=kinesis_data_json)
            payloads.append(payload)

        alerts = []
        for payload in payloads:
            # process payloads
            alerts.extend(StreamRules.process(payload))

        # check alert output
        assert_equal(len(alerts), 2)

        # alert tests
        assert_equal(alerts[0]['rule_name'], 'web_server')
        assert_equal(alerts[1]['rule_name'], 'data_location')

    def test_syslog_rule(self):
        @rule('syslog_sudo',
              logs=['test_log_type_syslog'],
              outputs=['s3'])
        def syslog_sudo(rec):
            return (
                rec['application'] == 'sudo' and
                'root' in rec['message']
            )

        kinesis_data = (
            'Jan 26 19:35:33 vagrant-ubuntu-trusty-64 '
            'sudo: pam_unix(sudo:session): '
            'session opened for user root by (uid=0)'
        )
        # prepare the payloads
        payload = self.make_kinesis_payload(kinesis_stream='test_stream_2',
                                            kinesis_data=kinesis_data)

        # process payloads
        alerts = StreamRules.process(payload)

        # alert tests
        assert_equal(len(alerts), 1)
        assert_equal(alerts[0]['rule_name'], 'syslog_sudo')
        assert_equal(alerts[0]['record']['host'], 'vagrant-ubuntu-trusty-64')
        assert_equal(alerts[0]['metadata']['type'], 'syslog')

    def test_csv_rule(self):
        @rule('nested_csv',
              logs=['test_log_type_csv_nested'],
              outputs=['pagerduty'])
        def nested_csv(rec):
            return (
                rec['message']['application'] == 'chef' and
                rec['message']['cluster_size'] == 100
            )

        kinesis_data = (
            '"Jan 10, 2017","1485739910","host1.prod.test","Corp",'
            '"chef,web-server,1,100,fail"'
        )
        # prepare the payloads
        payload = self.make_kinesis_payload(kinesis_stream='test_kinesis_stream',
                                            kinesis_data=kinesis_data)
        # process payloads
        alerts = StreamRules.process(payload)

        # alert tests
        assert_equal(len(alerts), 1)
        assert_equal(alerts[0]['rule_name'], 'nested_csv')

    def test_kv_rule(self):
        @rule('auditd_bin_cat',
              logs=['test_log_type_kv_auditd'],
              outputs=['pagerduty'])
        def auditd_bin_cat(rec):
            return (
                rec['type'] == 'SYSCALL' and
                rec['exe'] == '"/bin/cat"'
            )

        @rule('gid_500',
              logs=['test_log_type_kv_auditd'],
              outputs=['pagerduty'])
        def gid_500(rec):
            return (
                rec['gid'] == 500 and
                rec['euid'] == 500
            )

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
        # prepare the payloads
        payload = self.make_kinesis_payload(kinesis_stream='test_kinesis_stream',
                                            kinesis_data=auditd_test_data)
        # process payloads
        alerts = StreamRules.process(payload)

        # alert tests
        assert_equal(len(alerts), 2)

        rule_name_alerts = set([x['rule_name'] for x in alerts])
        assert_equal(rule_name_alerts, set(['gid_500', 'auditd_bin_cat']))
