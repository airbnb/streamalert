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
from streamalert.shared import CLUSTERED_FUNCTIONS
from streamalert_cli.utils import CLICommand


class StatusCommand(CLICommand):
    description = 'Output information on currently configured infrastructure'

    @classmethod
    def setup_subparser(cls, subparser):
        """manage.py status takes no arguments"""

    @classmethod
    def handler(cls, options, config):
        """Display current AWS infrastructure built by Terraform

        Args:
            config (CLIConfig): Loaded StreamAlert config

        Returns:
            bool: False if errors occurred, True otherwise
        """
        def _format_key(key):
            return key.replace('_', ' ').title()

        def _format_header(value, section_header=False):
            char = '=' if section_header else '+'
            value = value if section_header else _format_key(value)
            return '\n{value:{char}^60}'.format(char=char, value=f'  {value}  ')

        def _print_row(key, value):
            key = _format_key(key)
            print(f'{key}: {value}')

        print(_format_header('Global Account Settings', True))
        for key in sorted(['aws_account_id', 'prefix', 'region']):
            value = config['global']['account'][key]
            _print_row(key, value)

        lambda_keys = sorted([
            'concurrency_limit', 'enable_custom_metrics', 'log_level', 'log_retention_days',
            'memory', 'timeout', 'schedule_expression'
        ])
        for name in set(config['lambda']):
            config_value = config['lambda'][name]
            name = name.replace('_config', '')
            if name in CLUSTERED_FUNCTIONS:
                continue

            print(_format_header(name))
            for key in lambda_keys:
                _print_row(key, config_value.get(key))

        cluster_non_func_keys = sorted(['enable_threat_intel'])
        for cluster in sorted(config['clusters']):
            sa_config = config['clusters'][cluster]

            print(_format_header(f'Cluster: {cluster}', True))
            for key in cluster_non_func_keys:
                _print_row(key, sa_config.get(key))

            for function in CLUSTERED_FUNCTIONS:
                config_value = sa_config[f'{function}_config']

                print(_format_header(function))
                for key in lambda_keys:
                    _print_row(key, config_value.get(key))

        return True
