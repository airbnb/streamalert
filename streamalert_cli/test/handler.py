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
import argparse
from collections import defaultdict
import os

import jmespath
from mock import patch, MagicMock

from streamalert.alert_processor import main as alert_processor
from streamalert.alert_processor.helpers import compose_alert
from streamalert.alert_processor.outputs.output_base import OutputDispatcher
from streamalert.classifier import classifier
from streamalert.rules_engine import rules_engine
from streamalert.shared import rule
from streamalert.shared.logger import get_logger
from streamalert.shared.stats import RuleStatisticTracker
from streamalert_cli.helpers import check_credentials
from streamalert_cli.test.format import format_green, format_red, format_underline, format_yellow
from streamalert_cli.test.mocks import LookupTableMocks, ThreatIntelMocks
from streamalert_cli.test.event_file import TestEventFile
from streamalert_cli.utils import (
    CLICommand,
    DirectoryType,
    generate_subparser,
    UniqueSortedListAction,
)

LOGGER = get_logger(__name__)


class TestCommand(CLICommand):
    description = 'Perform various integration/functional tests'

    @classmethod
    def setup_subparser(cls, subparser):
        """Add the test subparser: manage.py test"""
        test_subparsers = subparser.add_subparsers(dest='test subcommand', required=True)

        cls._setup_test_classifier_subparser(test_subparsers)
        cls._setup_test_rules_subparser(test_subparsers)
        cls._setup_test_live_subparser(test_subparsers)

    @classmethod
    def _setup_test_classifier_subparser(cls, subparsers):
        """Add the test validation subparser: manage.py test classifier [options]"""
        test_validate_parser = generate_subparser(
            subparsers,
            'classifier',
            description='Validate defined log schemas using integration test files',
            subcommand=True
        )

        cls._add_default_test_args(test_validate_parser)

    @classmethod
    def _setup_test_rules_subparser(cls, subparsers):
        """Add the test rules subparser: manage.py test rules [options]"""
        test_rules_parser = generate_subparser(
            subparsers,
            'rules',
            description='Test rules using integration test files',
            subcommand=True
        )

        # Flag to run additional stats during testing
        test_rules_parser.add_argument(
            '-s',
            '--stats',
            action='store_true',
            help='Enable outputing of statistical information on rules that run'
        )

        # Validate the provided repitition value
        def _validate_repitition(val):
            """Make sure the input is between 1 and 1000"""
            err = ('Invalid repitition value [{}]. Must be an integer between 1 '
                   'and 1000').format(val)
            try:
                count = int(val)
            except TypeError:
                raise test_rules_parser.error(err)

            if not 1 <= count <= 1000:
                raise test_rules_parser.error(err)

            return count

        # flag to run these tests a given number of times
        test_rules_parser.add_argument(
            '-n',
            '--repeat',
            default=1,
            type=_validate_repitition,
            help='Number of times to repeat the tests, to be used as a form performance testing'
        )

        cls._add_default_test_args(test_rules_parser)

    @classmethod
    def _setup_test_live_subparser(cls, subparsers):
        """Add the test live subparser: manage.py test live [options]"""
        test_live_parser = generate_subparser(
            subparsers,
            'live',
            description=(
                'Run end-to-end tests that will attempt to send alerts to each rule\'s outputs'
            ),
            subcommand=True
        )

        cls._add_default_test_args(test_live_parser)

    @staticmethod
    def _add_default_test_args(test_parser):
        """Add the default arguments to the test parsers"""
        test_filter_group = test_parser.add_mutually_exclusive_group(required=False)

        # add the optional ability to test specific files
        test_filter_group.add_argument(
            '-f',
            '--test-files',
            dest='files',
            metavar='FILENAMES',
            nargs='+',
            help='One or more file to test, separated by spaces',
            action=UniqueSortedListAction,
            type=argparse.FileType('r'),
            default=[]
        )

        # add the optional ability to test specific rules
        test_filter_group.add_argument(
            '-r',
            '--test-rules',
            dest='rules',
            nargs='+',
            help='One or more rule to test, separated by spaces',
            action=UniqueSortedListAction,
            default=[]
        )

        # add the ability to specify rule directories to test
        test_parser.add_argument(
            '-d',
            '--rules-dir',
            help='Path to one or more directory containing rules, separated by spaces',
            nargs='+',
            action=UniqueSortedListAction,
            type=DirectoryType(),
            default=['rules']
        )

        # Add the optional ability to log verbosely or use quite logging for tests
        verbose_group = test_parser.add_mutually_exclusive_group(required=False)

        verbose_group.add_argument(
            '-v',
            '--verbose',
            action='store_true',
            help='Output additional information during testing'
        )

        verbose_group.add_argument(
            '-q',
            '--quiet',
            action='store_true',
            help='Suppress output for passing tests, only logging if there is a failure'
        )

    @classmethod
    def handler(cls, options, config):
        """Handler for starting the test framework

        Args:
            options (argparse.Namespace): Parsed arguments
            config (CLIConfig): Loaded StreamAlert config

        Returns:
            bool: False if errors occurred, True otherwise
        """
        result = True
        opts = vars(options)
        repeat = opts.get('repeat', 1)
        for i in range(repeat):
            if repeat != 1:
                print('\nRepetition #', i+1)
            result = result and TestRunner(options, config).run()

        if opts.get('stats'):
            print(RuleStatisticTracker.statistics_info())
        return result


class TestRunner:
    """TestRunner to handle running various tests"""

    class Types:
        """Simple types enum for test types"""
        CLASSIFY = 'classifier'
        RULES = 'rules'
        LIVE = 'live'

    def __init__(self, options, config):
        self._config = config
        self._options = options
        self._type = options.subcommand
        self._files_filter = {file.name for file in options.files} or set()
        self._rules = options.rules
        self._rules_dirs = options.rules_dir
        self._rules_engine = self._setup_rules_engine(options.rules_dir)
        self._verbose = options.verbose
        self._quiet = options.quiet
        self._s3_mocker = patch('streamalert.classifier.payload.s3.boto3.resource').start()
        self._errors = defaultdict(list)  # cache errors to be logged at the endpoint
        self._tested_rules = set()
        self._passed = 0
        self._failed = 0
        prefix = self._config['global']['account']['prefix']
        env = {
            'CLUSTER': 'prod',
            'STREAMALERT_PREFIX': prefix,
            'AWS_ACCOUNT_ID': self._config['global']['account']['aws_account_id'],
            'ALERTS_TABLE': '{}_streamalert_alerts'.format(prefix),
        }

        if 'stats' in options and options.stats:
            env['STREAMALERT_TRACK_RULE_STATS'] = '1'

        patch.dict(
            os.environ,
            env
        ).start()

    @staticmethod
    def _run_classification(record):
        """Create a fresh classifier and classify the record, returning the result"""
        with patch.object(classifier, 'SQSClient'), patch.object(classifier, 'FirehoseClient'):
            _classifier = classifier.Classifier()
            return _classifier.run(records=[record])

    @staticmethod
    @patch.object(rules_engine, 'AlertForwarder')
    @patch('rules.helpers.base.random_bool', return_value=True)
    @patch.object(rules_engine.RulesEngine, '_load_rule_table', return_value=None)
    def _setup_rules_engine(dirs, *_):
        """Create a fresh rules engine and process the record, returning the result"""
        return rules_engine.RulesEngine(*dirs)

    def _run_rules_engine(self, test_file_dir, record):
        """Create a fresh rules engine and process the record, returning the result"""
        with patch.object(rules_engine.ThreatIntel, '_query') as ti_mock:
            ti_mock.side_effect = ThreatIntelMocks.get_mock_values(test_file_dir)

            # pylint: disable=protected-access
            self._rules_engine._lookup_tables._tables.clear()
            for table in LookupTableMocks.get_mock_values(test_file_dir):
                if table.table_name in self._rules_engine._lookup_tables._tables:
                    continue
                self._rules_engine._lookup_tables._tables[table.table_name] = table

            return self._rules_engine.run(records=record)

    @staticmethod
    def _run_alerting(record):
        """Create a fresh alerts processor and send the alert(s), returning the result"""
        with patch.object(alert_processor, 'AlertTable'):
            alert_proc = alert_processor.AlertProcessor()

            return alert_proc.run(event=record.dynamo_record())

    def _check_prereqs(self):
        if self._type == self.Types.LIVE:
            return check_credentials()

        return True

    def _finalize(self):
        summary = [
            format_underline('\nSummary:\n'),
            'Total Tests: {}'.format(self._passed + self._failed),
            format_green('Pass: {}'.format(self._passed)) if self._passed else 'Pass: 0',
            format_red('Fail: {}\n'.format(self._failed)) if self._failed else 'Fail: 0\n',
        ]

        print('\n'.join(summary))

        for path in sorted(self._errors):
            for error in self._errors[path]:
                message = '({}) {}'.format(path, error) if path != 'error' else error
                LOGGER.error(message)

        # If rule are being tested and no filtering is being performed, log any untested rules
        if self._testing_rules and not self._is_filtered:
            all_rules = set(rule.Rule.rule_names()) - rule.Rule.disabled_rules()
            untested_rules = sorted(all_rules.difference(self._tested_rules))
            if not untested_rules:
                return
            print(format_yellow('No test events configured for the following rules:'))
            for rule_name in untested_rules:
                print(format_yellow(rule_name))

    @property
    def _is_filtered(self):
        return bool(self._files_filter or self._rules)

    @property
    def _testing_rules(self):
        return self._type in {self.Types.RULES, self.Types.LIVE}

    def _contains_filtered_rules(self, event):
        if not self._rules:
            return True

        expected_rules = set(event.trigger_rules) - rule.Rule.disabled_rules()
        return bool(expected_rules.intersection(self._rules))

    def _process_directory(self, directory):
        """Process rules and test files in the the rule directory"""
        print('\nRunning tests for files found in: {}'.format(directory))

        for root, event_files in self._get_test_files(directory):
            for event_file in event_files:
                full_path = os.path.join(root, event_file)
                if self._files_filter and full_path not in self._files_filter:
                    continue
                self._process_test_file(full_path)

    def _process_test_file(self, test_file_path):
        """Process an individual test file"""
        # Iterate over the individual test events in the file
        event_file = TestEventFile(test_file_path)
        for event in event_file.process_file(self._config, self._verbose, self._testing_rules):
            if not self._contains_filtered_rules(event):
                continue

            # Set the cluster in the env since this is used from within the
            # classifier to load the proper cluster config
            for cluster_name, cluster_value in self._config['clusters'].items():
                for service in cluster_value['data_sources'].values():
                    if event.source in service:
                        os.environ['CLUSTER'] = cluster_name
                        break

            classifier_result = self._run_classification(event.record)

            event.set_classified_result(classifier_result)
            if not event:
                continue

            if event.classify_only:
                continue  # Do not run rules on events that are only for validation

            self._tested_rules.update(event.expected_rules)

            test_file_dir = os.path.dirname(test_file_path) + os.path.sep
            if self._type in {self.Types.RULES, self.Types.LIVE}:
                event.alerts = self._run_rules_engine(
                    test_file_dir,
                    event.classified_log.sqs_messages
                )

                if event.publisher_tests:
                    for alert in event.alerts:
                        publication_results = self._run_publishers(alert)

                        publisher_test_results = []
                        for output, individual_tests in event.publisher_tests.items():
                            for publisher_test in individual_tests:
                                if not isinstance(publisher_test, list) or len(publisher_test) != 3:
                                    publisher_test_results.append({
                                        'success': False,
                                        'error': (
                                            'Invalid publisher test specified: {}'
                                            'Publisher test must be a triple with elements: '
                                            '(jsonpath, condition, condition_value)'
                                        ).format(publisher_test),
                                        'output_descriptor': output,
                                    })
                                    continue

                                jsonpath, condition, condition_value = publisher_test

                                if output not in publication_results:
                                    publisher_test_results.append({
                                        'success': False,
                                        'error': (
                                            'No such output {} was configured for this alert'
                                        ).format(output),
                                        'output_descriptor': output,
                                    })
                                    continue

                                publication = publication_results[output]['publication']

                                subject_value = jmespath.search(jsonpath, publication)

                                if condition == 'is':
                                    res = subject_value == condition_value
                                elif condition == 'in':
                                    if isinstance(condition_value, list):
                                        res = subject_value in condition_value
                                    else:
                                        res = condition_value.contains(subject_value)
                                else:
                                    publisher_test_results.append({
                                        'success': False,
                                        'error': (
                                            'Invalid condition specified: {}\n'
                                            'Valid conditions are: {}'
                                        ).format(condition, ['is', 'in']),
                                        'output_descriptor': output,
                                    })
                                    continue

                                publisher_test_results.append({
                                    'success': res,
                                    'failure': None if res else (
                                        'Item at path "{}" {} "{}",\nActual value: "{}"'.format(
                                            jsonpath,
                                            (
                                                "should have been" if condition == 'is'
                                                else "should have contained"
                                            ),
                                            condition_value,
                                            subject_value
                                        )
                                    ),
                                    'output_descriptor': output
                                })

                        event.set_publication_results(publisher_test_results)


                if self._type == self.Types.LIVE:
                    for alert in event.alerts:
                        alert_result = self._run_alerting(alert)
                        event.add_live_test_result(alert.rule_name, alert_result)

        self._passed += event_file.passed
        self._failed += event_file.failed

        # It is possible for a test_event to have no results, but contain errors
        # so only print it if it does and if quiet mode is not being used
        # Quite mode is overridden if not all of the events passed
        if event_file.error or not (self._quiet and event_file.all_passed):
            print(event_file)

    def run(self):
        """Run the tests"""
        if not self._check_prereqs():
            return

        for directory in self._rules_dirs:
            # The CLI checks if these directories exist, so no need to check here
            self._process_directory(directory)

        self._finalize()

        return self._failed == 0

    @staticmethod
    def _run_publishers(alert):
        """Runs publishers for all currently configured outputs on the given alert

        Args:
            - alert (Alert): The alert

        Returns:
            dict: A dict keyed by output:descriptor strings, mapped to nested dicts.
                self._rules_engine._lookup_tables  The nested dicts have 2 keys:
                  - publication (dict): The dict publication
                  - success (bool): True if the publishing finished, False if it errored.
        """
        configured_outputs = alert.outputs

        results = {}
        for configured_output in configured_outputs:
            [output_name, descriptor] = configured_output.split(':')

            try:
                output = MagicMock(spec=OutputDispatcher, __service__=output_name)
                results[configured_output] = {
                    'publication': compose_alert(alert, output, descriptor),
                    'success': True,
                }
            except (RuntimeError, TypeError, NameError) as err:
                results[configured_output] = {
                    'success': False,
                    'error': err,
                }
        return results

    def _handle_fixtures(self, rule_dir, setup=True):
        path = os.path.join(rule_dir, 'test_fixtures')
        message = '{} fixtures in: %s'.format('Setting up' if setup else 'Tearing down')
        LOGGER.debug(message, path)
        for item in os.listdir(path):
            directory = os.path.join(path, item)
            if not os.path.isdir(directory):
                continue

            if item == 'lookup_tables':
                if setup:
                    self._setup_lookup_table_fixtures(rule_dir)
                else:
                    self._teardown_lookup_table_fixtures(rule_dir)
            elif item == 'threat_intel':
                if setup:
                    self._setup_threat_intel_fixtures(rule_dir)
                else:
                    self._teardown_threat_intel_fixtures(rule_dir)
            else:
                LOGGER.warning('Unsupported fixture directory: %s', directory)

    @staticmethod
    def _setup_lookup_table_fixtures(rule_dir):
        LookupTableMocks.add_fixtures(rule_dir)

    @staticmethod
    def _setup_threat_intel_fixtures(rule_dir):
        ThreatIntelMocks.add_fixtures(rule_dir)

    @staticmethod
    def _teardown_lookup_table_fixtures(rule_dir):
        LookupTableMocks.remove_fixtures(rule_dir)

    @staticmethod
    def _teardown_threat_intel_fixtures(rule_dir):
        ThreatIntelMocks.remove_fixtures(rule_dir)

    def _teardown_all_fixtures(self, fixtures):
        LOGGER.debug('Tearing down all fixtures')
        for fixture_path in fixtures:
            self._handle_fixtures(fixture_path, setup=False)

    def skip_fixtures(self, cached_fixtures, root):
        for parent in list(cached_fixtures):
            fixture_path = cached_fixtures[parent]
            # What to do with fixture_path
            if not root.startswith(parent):
                self._handle_fixtures(parent, setup=False)
                LOGGER.debug('Deleting fixture path from cache: %s', parent)
                del cached_fixtures[parent]
            elif root.startswith(fixture_path):
                return True

    def _get_test_files(self, directory):
        """Helper to get rule test files

        Yields:
            str: Path to test event file
        """
        cached_fixtures = dict()
        for root, cur_dirs, test_event_files in os.walk(directory):
            root += os.path.sep
            # Teardown any fixtures that are not needed for this directory
            if self.skip_fixtures(cached_fixtures, root):
                LOGGER.debug('Skipping fixtures dir that has been setup: %s', root)
                continue

            if 'test_fixtures' in set(cur_dirs):
                fixture_path = os.path.join(root, 'test_fixtures')
                self._handle_fixtures(root, setup=True)
                LOGGER.debug('Caching fixture path: %s', fixture_path)
                cached_fixtures[root] = fixture_path

            # Simple filter to remove any non-json files first
            files = [
                file for file in sorted(test_event_files)
                if os.path.splitext(file)[1] == '.json'
            ]
            if not files:
                continue

            yield root, files

        self._teardown_all_fixtures(cached_fixtures)
