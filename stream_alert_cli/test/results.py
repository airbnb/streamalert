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
from collections import defaultdict
import textwrap

from stream_alert.shared import rule
from stream_alert_cli.test.format import format_green, format_red, format_underline


class TestEventFile(object):
    """TestEventFile handles caching results of test events within a test file"""

    def __init__(self, rel_path):
        self._rel_path = rel_path
        self._results = []

    def __nonzero__(self):
        return bool(self._results)

    # For forward compatibility to Python3
    __bool__ = __nonzero__

    @property
    def all_passed(self):
        return self.passed == len(self._results)

    @property
    def passed(self):
        return sum(1 for result in self._results if result.passed)

    @property
    def failed(self):
        return sum(1 for result in self._results if not result.passed)

    def add_result(self, result):
        self._results.append(result)

    def __str__(self):
        output = [format_underline('\nFile: {file_name}\n'.format(file_name=self._rel_path))]

        for result in self._results:
            output.append(result)

        return '\n'.join(str(item) for item in output)


class TestResult(object):
    """TestResult contains information useful for tracking test results"""

    _NONE_STRING = '<None>'
    _PASS_STRING = format_green('Pass')
    _FAIL_STRING = format_red('Fail')
    _SIMPLE_TEMPLATE = '{header}:'
    _CLASSIFICATION_STATUS_TEMPLATE = '  Classification: {classification_status}'
    _RULES_STATUS_TEMPLATE = '  Rules: {rules_status}'
    _PUBLISHERS_STATUS_TEMPLATE = '  Publishers: {publishers_status}'
    _VERBOSE_TEMPLATE = (
        '''
            Description: {description}
            Classified Type: {classified_type}
            Expected Type: {expected_type}'''
    )

    _VALIDATION_ONLY = (
        '''
            Validation Only: True'''
    )

    _RULES_TEMPLATE = (
        '''
            Triggered Rules: {triggered_rules}
            Expected Rules: {expected_rules}'''
    )

    _DISABLED_RULES_TEMPLATE = (
        '''
            Disabled Rules: {disabled_rules}'''
    )

    _ALERTS_TEMPLATE = (
        '''
            Sent Alerts: {sent_alerts}
            Failed Alerts: {failed_alerts}'''
    )

    _PUBLISHERS_TEMPLATE = (
        '''
            Publisher Errors:
                {publisher_errors}'''
    )
    _DEFAULT_INDENT = 4

    def __init__(self, index, test_event, classified_result, with_rules=False, verbose=False):
        self._idx = index
        self._test_event = test_event
        self._classified_result = classified_result
        self._with_rules = with_rules
        self._verbose = verbose
        self._live_test_results = {}
        self._publication_results = {}
        self.alerts = []

    def __nonzero__(self):
        return bool(self._classified_result)

    # For forward compatibility to Python3
    __bool__ = __nonzero__

    def __str__(self):
        # Store the computed property
        passed = self.passed

        template = self._SIMPLE_TEMPLATE + '\n' + self._CLASSIFICATION_STATUS_TEMPLATE
        fmt = {
            'header': 'Test #{idx:02d}'.format(idx=self._idx + 1),
            'classification_status': (
                self._PASS_STRING if self.classification_status_passed else self._FAIL_STRING
            )
        }

        if self.rules_run:
            template += '\n' + self._RULES_STATUS_TEMPLATE
            fmt['rules_status'] = (
                self._PASS_STRING if self.rules_status_passed else self._FAIL_STRING
            )

        if self.publishers_run:
            template += '\n' + self._PUBLISHERS_STATUS_TEMPLATE

            num_pass = 0
            num_total = 0
            for _, result in self._publication_results.iteritems():
                num_total += 1
                num_pass += 1 if result['success'] else 0
            fmt['publishers_status'] = (
                format_green('{}/{} Passed'.format(num_pass, num_total))
                if num_pass == num_total
                else format_red('{}/{} Passed'.format(num_pass, num_total))
            )

        if passed and not self._verbose:
            return template.format(**fmt)

        # Intent all lines in the original template
        right_justified_lines = '\n'.join(
            [i.rjust(len(i) + self._DEFAULT_INDENT * 2) for i in template.split('\n')]
        )
        template = '{}\n{}'.format(
            right_justified_lines,
            self._VERBOSE_TEMPLATE
        )
        fmt['description'] = self._test_event['description']
        fmt['expected_type'] = self._test_event['log']
        fmt['classified_type'] = (
            self._classified_result.log_schema_type
            if self._classified else format_red(
                self._classified_result.log_schema_type
                if self else self._NONE_STRING
            )
        )

        if self._test_event.get('validate_schema_only'):
            line = 'Validation Only: True'
            template += '\n' + line.rjust(len(line) + self._DEFAULT_INDENT * 3)
        elif self._with_rules:
            template += self._RULES_TEMPLATE
            fmt['triggered_rules'] = self._format_rules(
                self._triggered_rules,
                self.expected_rules
            )

            fmt['expected_rules'] = self._format_rules(
                self.expected_rules,
                self._triggered_rules
            )

            disabled = self._disabled_rules
            if disabled:
                template += self._DISABLED_RULES_TEMPLATE
                fmt['disabled_rules'] = ', '.join(disabled)

            if self._live_test_results:
                template += self._ALERTS_TEMPLATE
                fmt['sent_alerts'], fmt['failed_alerts'] = self._format_alert_results()

        if self.publishers_run:
            template += self._PUBLISHERS_TEMPLATE
            fmt['publisher_errors'] = format_red(self.publisher_errors)

        return textwrap.dedent(template.format(**fmt)).rstrip() + '\n'

    __repr__ = __str__

    @property
    def _disabled_rules(self):
        return sorted(set(self._test_event.get('trigger_rules', [])).intersection(
            rule.Rule.disabled_rules()
        ))

    @property
    def _triggered_rules(self):
        return {alert.rule_name for alert in self.alerts}

    @property
    def _untriggered_rules(self):
        return sorted(self.expected_rules.difference(self._triggered_rules))

    @property
    def expected_rules(self):
        return set(self._test_event.get('trigger_rules', [])) - rule.Rule.disabled_rules()

    @property
    def _unexpected_rules(self):
        return sorted(self._triggered_rules.difference(self.expected_rules))

    @property
    def _classified(self):
        if not self:
            return False

        return self._classified_result.log_schema_type == self._test_event['log']

    def _format_rules(self, items, compare_set):
        if not items:
            return self._NONE_STRING

        all_rules = set(rule.Rule.rule_names())

        result = []
        for value in sorted(items):
            if value not in all_rules:
                value = '{} (does not exist)'.format(value)

            result.append(format_red(value) if value not in compare_set else value)
        return ', '.join(result)

    def _format_alert_results(self):
        failed = defaultdict(list)
        success = defaultdict(list)
        for rule_name in sorted(self._live_test_results):
            result = self._live_test_results[rule_name]
            for output, status in result.iteritems():
                if not status:
                    failed[rule_name].append(output)
                else:
                    success[rule_name].append(output)

        return self._alert_result_block(success), self._alert_result_block(failed, True)

    def _alert_result_block(self, values, failed=False):
        result_block = []
        fmt = '{pad_char:<{pad}}{line}'
        for rule_name in sorted(values):
            result_block.append(
                fmt.format(
                    pad_char=' ',
                    pad=self._DEFAULT_INDENT * 4,
                    line='Rule: {rule_name}'.format(rule_name=format_underline(rule_name))
                )
            )

            result_block.extend(
                fmt.format(
                    pad_char=' ',
                    pad=self._DEFAULT_INDENT * 5,
                    line=format_red(value) if failed else value
                )
                for value in values[rule_name]
            )

        return self._NONE_STRING if not result_block else '\n{}'.format('\n'.join(result_block))

    @property
    def rules_run(self):
        return not self._test_event.get('validate_schema_only') and self._with_rules

    @property
    def publishers_run(self):
        return (
            self.rules_run
            and not self._test_event.get('skip_publishers')
            and self._publication_results
        )

    @property
    def classification_status_passed(self):
        return self._classified

    @property
    def rules_status_passed(self):
        return self.rules_run and (self._triggered_rules == self.expected_rules)

    @property
    def has_live_tests(self):
        return self._live_test_results

    @property
    def live_tests_status_passed(self):
        for result in self._live_test_results.itervalues():
            if not all(status for status in result.itervalues()):
                return False
        return True

    @property
    def publishers_status_passed(self):
        if not self.rules_run:
            return False

        for _, result in self._publication_results.iteritems():
            if not result['success']:
                return False

        return True

    @property
    def publisher_errors(self):
        if not self.publishers_run:
            return []

        return [
            item['error']
            for _, item
            in self._publication_results.iteritems()
            if not item['success']
        ]

    @property
    def count_publisher_tests_passed(self):
        return sum(1 for _, result in self._publication_results.iteritems() if result['success'])

    @property
    def count_publisher_tests_run(self):
        return len(self._publication_results)

    @property
    def passed(self):
        """A test has passed if it meets the following criteria:

        1) The log has classified as the correct type
        2) If rules are being tested, all triggered rules match expected rules
        3) If a live test is being performed, all alerts sent to outputs successfully
        """
        if not self.classification_status_passed:
            return False

        if not self.rules_run:
            return True

        if not self.rules_status_passed:
            return False

        if not self.live_tests_status_passed:
            return False

        if not self.publishers_status_passed:
            return False

        return True

    def set_publication_results(self, publication_results):
        self._publication_results = publication_results

    def add_live_test_result(self, rule_name, result):
        self._live_test_results[rule_name] = result
