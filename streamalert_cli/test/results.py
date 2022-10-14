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
import textwrap
from collections import defaultdict

from streamalert.shared import rule
from streamalert.shared.logger import get_logger
from streamalert_cli.test.event import TestEvent
from streamalert_cli.test.format import (format_green, format_red,
                                         format_underline)

LOGGER = get_logger(__name__)


class TestResult(TestEvent):
    """TestResult contains information useful for tracking test results"""

    _NONE_STRING = '<None>'
    _PASS_STRING = format_green('Pass')
    _FAIL_STRING = format_red('Fail')
    _SIMPLE_TEMPLATE = '{header}:'
    _PASS_TEMPLATE = '{header}: {pass}'  # nosec
    _ERROR_TEMPLATE = '{header}: {error}'  # nosec
    _DESCRIPTION_LINE = ('''
    Description: {description}''')
    _CLASSIFICATION_STATUS_TEMPLATE = ('''
    Classification: {classification_status}
        Classified Type: {classified_type}
        Expected Type: {expected_type}''')
    _RULES_STATUS_TEMPLATE = ('''
    Rules: {rules_status}
        Triggered Rules: {triggered_rules}
        Expected Rules: {expected_rules}''')
    _DISABLED_RULES_TEMPLATE = ('''
        Disabled Rules: {disabled_rules}''')
    _PUBLISHERS_STATUS_TEMPLATE = ('''
    Publishers: {publishers_status}
        Errors:
{publisher_errors}''')
    _CLASSIFY_ONLY = ('''
    Classify Only: True''')
    _ALERTS_TEMPLATE = ('''
    Live Alerts:
        Sent Alerts: {sent_alerts}
        Failed Alerts: {failed_alerts}''')
    _DEFAULT_INDENT = 4

    def __init__(self, idx, test_event, verbose=False, with_rules=False):
        super().__init__(test_event)
        self._index = idx
        self._with_rules = with_rules
        self._verbose = verbose
        self._classified_result = None
        self._live_test_results = {}
        self._publication_results = {}
        self.alerts = []

    def __bool__(self):
        return bool(self._classified_result)

    def __str__(self):
        fmt = {
            'header': f'Test #{self._index + 1:02d}',
        }

        if self.error:
            fmt['error'] = format_red(f'Error - {self.error}')
            return self._ERROR_TEMPLATE.format(**fmt)

        if self.passed and not self._verbose:
            # Simply render "Test #XYZ: Pass" if the whole test case passed
            fmt['pass'] = self._PASS_STRING
            return self._PASS_TEMPLATE.format(**fmt)

        # Otherwise, expand the entire test with verbose details
        template = self._SIMPLE_TEMPLATE + '\n' + self._DESCRIPTION_LINE
        fmt['description'] = self.description

        # First, render classification
        template += '\n' + self._CLASSIFICATION_STATUS_TEMPLATE
        fmt['classification_status'] = (self._PASS_STRING
                                        if self.classification_tests_passed else self._FAIL_STRING)
        fmt['expected_type'] = self.log
        fmt['classified_type'] = (
            self._classified_result.log_schema_type if self._classified else
            format_red(self._classified_result.log_schema_type if self else self._NONE_STRING))

        # If it was classification-only, note it down
        if self.classify_only:
            template += self._CLASSIFY_ONLY

        # Render the result of rules engine run
        if self.rule_tests_were_run:
            template += '\n' + self._RULES_STATUS_TEMPLATE
            fmt['rules_status'] = (self._PASS_STRING
                                   if self.rule_tests_passed else self._FAIL_STRING)
            fmt['triggered_rules'] = self._format_rules(self._triggered_rules, self.expected_rules)

            fmt['expected_rules'] = self._format_rules(self.expected_rules, self._triggered_rules)

            if disabled := self._disabled_rules:
                template += self._DISABLED_RULES_TEMPLATE
                fmt['disabled_rules'] = ', '.join(disabled)

            # Render live test results
            if self.has_live_tests:
                template += self._ALERTS_TEMPLATE
                fmt['sent_alerts'], fmt['failed_alerts'] = self._format_alert_results()

        # Render any publisher errors
        if self.publisher_tests_were_run:
            template += '\n' + self._PUBLISHERS_STATUS_TEMPLATE

            num_pass = 0
            num_total = 0
            for num_total, result in enumerate(self._publication_results, start=1):
                num_pass += 1 if result['success'] else 0

            fmt['publishers_status'] = format_green(
                f'{num_pass}/{num_total} Passed') if num_pass == num_total else format_red(
                    f'{num_pass}/{num_total} Passed')

            pad = ' ' * self._DEFAULT_INDENT * 3
            fmt['publisher_errors'] = format_red('\n'.join([
                f'{pad}{error}' for error in self.publisher_errors
            ])) if self.publisher_errors else f'{pad}{self._NONE_STRING}'

        return textwrap.dedent(template.format(**fmt)).rstrip() + '\n'

    __repr__ = __str__

    @property
    def index(self):
        return self._index

    @property
    def _disabled_rules(self):
        return sorted(set(self.trigger_rules).intersection(rule.Rule.disabled_rules()))

    @property
    def _triggered_rules(self):
        return {alert.rule_name for alert in self.alerts}

    @property
    def _untriggered_rules(self):
        return sorted(self.expected_rules.difference(self._triggered_rules))

    @property
    def expected_rules(self):
        return set(self.trigger_rules) - rule.Rule.disabled_rules()

    @property
    def classified_log(self):
        return self._classified_result

    @property
    def _unexpected_rules(self):
        return sorted(self._triggered_rules.difference(self.expected_rules))

    @property
    def _classified(self):
        return self and self._classified_result.log_schema_type == self.log

    def _format_rules(self, items, compare_set):
        if not items:
            return self._NONE_STRING

        all_rules = set(rule.Rule.rule_names())

        result = []
        for value in sorted(items):
            if value not in all_rules:
                value = f'{value} (does not exist)'

            result.append(format_red(value) if value not in compare_set else value)
        return ', '.join(result)

    def _format_alert_results(self):
        failed = defaultdict(list)
        success = defaultdict(list)
        for rule_name in sorted(self._live_test_results):
            result = self._live_test_results[rule_name]
            for output, status in result.items():
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
                fmt.format(pad_char=' ',
                           pad=self._DEFAULT_INDENT * 4,
                           line=f'Rule: {format_underline(rule_name)}'))

            result_block.extend(
                fmt.format(pad_char=' ',
                           pad=self._DEFAULT_INDENT * 5,
                           line=format_red(value) if failed else value)
                for value in values[rule_name])

        return '\n{}'.format('\n'.join(result_block)) if result_block else self._NONE_STRING

    @property
    def rule_tests_were_run(self):
        """Returns True if this testcase ran Rules Engine tests"""
        return not self.classify_only and self._with_rules

    @property
    def publisher_tests_were_run(self):
        """Returns True if this test ran Publisher tests for each output"""
        return self.rule_tests_were_run and not self.skip_publishers and self._publication_results

    @property
    def classification_tests_passed(self):
        """Returns True if all classification tests passed"""
        return self._classified

    @property
    def rule_tests_passed(self):
        """Returns True if all rules engine tests passed

        Also returns False if the rules engine tests were not run
        """
        return self.rule_tests_were_run and (self._triggered_rules == self.expected_rules)

    @property
    def has_live_tests(self):
        """Returns True if this testcase ran any live tests"""
        return self._live_test_results

    @property
    def live_tests_passed(self):
        """Returns True if all live tests passed

        Also returns False if live tests were not run
        """
        return all(all(result.values())
                   for result in self._live_test_results.values()) if self.has_live_tests else False

    @property
    def publisher_tests_passed(self):
        """Returns True if all publisher tests were passed

        Also returns False if publisher tests were not run
        """
        return all(
            result['success']
            for result in self._publication_results) if self.publisher_tests_were_run else False

    @property
    def publisher_errors(self):
        """Returns an array of strings describing errors in the publisher tests

        The strings take the form:

            [output:descriptor]: (Error Type) Error message
        """
        return ([
        f"""{item['output_descriptor']}: {f"({type(item['error']).__name__}) {item['error']}" if 'error' in item else item['failure']}"""
        for item in self._publication_results if not item['success']] if self.publisher_tests_were_run else [])

    @property
    def count_publisher_tests_passed(self):
        """Returns number of publisher tests that failed"""
        return sum(1 for _, result in self._publication_results.items() if result['success'])

    @property
    def count_publisher_tests_run(self):
        """Returns total number of publisher tests"""
        return len(self._publication_results)

    @property
    def passed(self):
        """A test has passed if it meets the following criteria:

        1) The log has classified as the correct type
        2) If rules are being tested, all triggered rules match expected rules
        3) If a live test is being performed, all alerts sent to outputs successfully
        """
        if not self.classification_tests_passed:
            return False

        if self.rule_tests_were_run and not self.rule_tests_passed:
            return False

        if self.has_live_tests and not self.live_tests_passed:
            return False

        return bool(not self.publisher_tests_were_run or self.publisher_tests_passed)

    def set_classified_result(self, classified_result):
        self._classified_result = classified_result[0] if classified_result else None

    def set_publication_results(self, publication_results):
        """

        Params
            publication_results (list[dict]):
                A list of dictionaries that describe the result of running publications tests.
                Each dictionary should contain the following:

                - output_descriptor: The output the test is run on
                - expectation: String describing the test: (e.g. "[$.slack] should be value")
                - error: If an ERROR was encountered, this is the error
                - failure: If the test did not pass, describe why
                - success: True if test passed. False otherwise.
        """
        self._publication_results = publication_results

    def add_live_test_result(self, rule_name, result):
        self._live_test_results[rule_name] = result
