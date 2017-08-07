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

from nose.tools import assert_equal, assert_is_instance, assert_items_equal

from stream_alert.rule_processor.classifier import StreamClassifier
from stream_alert.rule_processor.payload import StreamPayload
from stream_alert.rule_processor.config import load_config
from stream_alert.rule_processor.rules_engine import StreamRules

from stream_alert.rule_processor.config import load_env

from unit.stream_alert_rule_processor.test_helpers import (
    _get_mock_context,
    _load_and_classify_payload,
    _make_kinesis_raw_record
)

rule = StreamRules.rule
matcher = StreamRules.matcher()
disable = StreamRules.disable()


class TestStreamRules(object):
    """Test class for StreamRules"""
    @classmethod
    def setup_class(cls):
        """Setup the class before any methods"""
        context = _get_mock_context()
        cls.env = load_env(context)
        cls.config = load_config('test/unit/conf')

    @classmethod
    def teardown_class(cls):
        """Teardown the class after all methods"""
        cls.env = None
        cls.config = None

    def test_alert_format(self):
        """Rule Engine - Alert Format"""
        @rule(logs=['test_log_type_json_nested_with_data'],
              outputs=['s3:sample_bucket'])
        def alert_format_test(rec):
            """'alert_format_test' docstring for testing rule_description"""
            return rec['application'] == 'web-app'

        kinesis_data = json.dumps({
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
        })

        # prepare the payloads
        service, entity = 'kinesis', 'test_kinesis_stream'
        raw_record = _make_kinesis_raw_record(entity, kinesis_data)
        payload = _load_and_classify_payload(self.config, service, entity, raw_record)

        # process payloads
        alerts = StreamRules.process(payload)

        alert_keys = {
            'record',
            'rule_name',
            'rule_description',
            'log_type',
            'log_source',
            'outputs',
            'source_service',
            'source_entity'
        }
        assert_items_equal(alerts[0].keys(), alert_keys)
        assert_is_instance(alerts[0]['record'], dict)
        assert_is_instance(alerts[0]['outputs'], list)

        # test alert fields
        assert_is_instance(alerts[0]['rule_name'], str)
        assert_is_instance(alerts[0]['rule_description'], str)
        assert_is_instance(alerts[0]['outputs'], list)
        assert_is_instance(alerts[0]['log_type'], str)
        assert_is_instance(alerts[0]['log_source'], str)

    def test_basic_rule_matcher_process(self):
        """Rule Engine - Basic Rule/Matcher"""
        @matcher
        def prod(rec):
            return rec['environment'] == 'prod'

        @rule()
        def incomplete_rule(rec):
            return True

        @rule(logs=['test_log_type_json_nested_with_data'],
              outputs=['s3:sample_bucket'])
        def minimal_rule(rec):
            return rec['unixtime'] == 1483139547

        @rule(matchers=['foobar', 'prod'],
              logs=['test_log_type_json_nested_with_data'],
              outputs=['pagerduty:sample_integration'])
        def chef_logs(rec):
            return rec['application'] == 'chef'

        @rule(matchers=['foobar', 'prod'],
              logs=['test_log_type_json_nested_with_data'],
              outputs=['pagerduty:sample_integration'])
        def test_nest(rec):
            return rec['data']['source'] == 'eu'

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
        service, entity = 'kinesis', 'test_kinesis_stream'
        raw_record = _make_kinesis_raw_record(entity, json.dumps(kinesis_data))
        payload = _load_and_classify_payload(self.config, service, entity, raw_record)

        # process payloads
        alerts = StreamRules.process(payload)

        # check alert output
        assert_equal(len(alerts), 3)
        rule_outputs_map = {
            'chef_logs': ['pagerduty:sample_integration'],
            'minimal_rule': ['s3:sample_bucket'],
            'test_nest': ['pagerduty:sample_integration']
        }
        # doing this because after kinesis_data is read in, types are casted per the schema
        for alert in alerts:
            assert_items_equal(alert['record'].keys(), kinesis_data.keys())
            assert_items_equal(alert['outputs'], rule_outputs_map[alert['rule_name']])


    def test_process_req_subkeys(self):
        """Rule Engine - Req Subkeys"""
        @rule(logs=['test_log_type_json_nested'],
              outputs=['s3:sample_bucket'],
              req_subkeys={'data': ['location']})
        def data_location(rec):
            return rec['data']['location'].startswith('us')

        @rule(logs=['test_log_type_json_nested'],
              outputs=['s3:sample_bucket'],
              req_subkeys={'data': ['category']})
        def web_server(rec):
            return rec['data']['category'] == 'web-server'

        kinesis_data_items = [
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
        alerts = []
        for data in kinesis_data_items:
            kinesis_data = json.dumps(data)
            # prepare the payloads
            service, entity = 'kinesis', 'test_kinesis_stream'
            raw_record = _make_kinesis_raw_record(entity, kinesis_data)
            payload = _load_and_classify_payload(self.config, service, entity, raw_record)

            alerts.extend(StreamRules.process(payload))

        # check alert output
        assert_equal(len(alerts), 2)

        # alert tests
        assert_equal(alerts[0]['rule_name'], 'web_server')
        assert_equal(alerts[1]['rule_name'], 'data_location')

    def test_syslog_rule(self):
        """Rule Engine - Syslog Rule"""
        @rule(logs=['test_log_type_syslog'],
              outputs=['s3:sample_bucket'])
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
        service, entity = 'kinesis', 'test_stream_2'
        raw_record = _make_kinesis_raw_record(entity, kinesis_data)
        payload = _load_and_classify_payload(self.config, service, entity, raw_record)

        # process payloads
        alerts = StreamRules.process(payload)

        # alert tests
        assert_equal(len(alerts), 1)
        assert_equal(alerts[0]['rule_name'], 'syslog_sudo')
        assert_equal(alerts[0]['record']['host'], 'vagrant-ubuntu-trusty-64')
        assert_equal(alerts[0]['log_type'], 'syslog')

    def test_csv_rule(self):
        """Rule Engine - CSV Rule"""
        @rule(logs=['test_log_type_csv_nested'],
              outputs=['pagerduty:sample_integration'])
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
        service, entity = 'kinesis', 'test_kinesis_stream'
        raw_record = _make_kinesis_raw_record(entity, kinesis_data)
        payload = _load_and_classify_payload(self.config, service, entity, raw_record)

        # process payloads
        alerts = StreamRules.process(payload)

        # alert tests
        assert_equal(len(alerts), 1)
        assert_equal(alerts[0]['rule_name'], 'nested_csv')

    def test_rule_disable(self):
        """Rule Engine - Disable Rule"""
        @disable
        @rule(logs=['test_log_type_json_2'],
              outputs=['pagerduty:sample_integration'])
        def nested_csv_disable_test(rec):
            return rec['host'] == 'unit-test-host.prod.test'

        kinesis_data = json.dumps({
            'key4': True,
            'key5': 0.0,
            'key6': 1,
            'key7': False
        })

        # prepare the payloads
        service, entity = 'kinesis', 'test_kinesis_stream'
        raw_record = _make_kinesis_raw_record(entity, kinesis_data)
        payload = _load_and_classify_payload(self.config, service, entity, raw_record)

        # process payloads
        alerts = StreamRules.process(payload)

        # alert tests
        assert_equal(len(alerts), 0)

    def test_kv_rule(self):
        """Rule Engine - KV Rule"""
        @rule(logs=['test_log_type_kv_auditd'],
              outputs=['pagerduty:sample_integration'])
        def auditd_bin_cat(rec):
            return (
                rec['type'] == 'SYSCALL' and
                rec['exe'] == '"/bin/cat"'
            )

        @rule(logs=['test_log_type_kv_auditd'],
              outputs=['pagerduty:sample_integration'])
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
        service, entity = 'kinesis', 'test_kinesis_stream'
        raw_record = _make_kinesis_raw_record(entity, auditd_test_data)
        payload = _load_and_classify_payload(self.config, service, entity, raw_record)

        # process payloads
        alerts = StreamRules.process(payload)

        # alert tests
        assert_equal(len(alerts), 2)

        rule_name_alerts = [x['rule_name'] for x in alerts]
        assert_items_equal(rule_name_alerts, ['gid_500', 'auditd_bin_cat'])
