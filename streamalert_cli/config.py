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
import json
import os
import re
import shutil
import string
import tempfile

from streamalert.apps import StreamAlertApp
from streamalert.shared import CLUSTERED_FUNCTIONS, config, metrics
from streamalert.shared.logger import get_logger
from streamalert_cli.apps.helpers import save_app_auth_info
from streamalert_cli.helpers import continue_prompt
from streamalert_cli.terraform import TERRAFORM_FILES_PATH

DEFAULT_CONFIG_PATH = 'conf'
LOGGER = get_logger(__name__)


class CLIConfig:
    """A class to load, modify, and display the StreamAlertCLI Config"""
    def __init__(self, config_path, extra_terraform_files=None, build_directory=None):
        self.config_path = config_path
        self.config = config.load_config(config_path)
        self._terraform_files = extra_terraform_files or []
        self.build_directory = self._setup_build_directory(build_directory)

    def __repr__(self):
        return str(self.config)

    def __getitem__(self, key):
        return self.config[key]

    def __setitem__(self, key, new_value):
        self.config.__setitem__(key, new_value)
        self.write()

    def get(self, key, default=None):
        """Lookup a value based on its key"""
        return self.config.get(key, default)

    def keys(self):
        """Config keys"""
        return list(self.config.keys())

    def clusters(self):
        """Return list of cluster configuration keys"""
        return list(self.config['clusters'].keys())

    @property
    def terraform_files(self):
        """Return set of terraform files to include with this deployment"""
        return set(self._terraform_files).union(self.config['global']['general'].get(
            'terraform_files', []))

    def _copy_terraform_files(self, directory):
        """Copy all packaged terraform files and terraform files provided by the user to temp

        Args:
            config (CLIConfig): Loaded StreamAlert config
        """
        shutil.copytree(TERRAFORM_FILES_PATH, directory)

        # Copy any additional user provided terraform files to temp
        for item in self.terraform_files:
            shutil.copy2(item, directory)

        LOGGER.info('Copied Terraform configuration to \'%s\'', directory)

    def _setup_build_directory(self, directory):
        """Create the directory to be used for building infrastructure

        Args:
            directory (str): Optional path to directory to create

        Returns:
            str: Path to directory that will be used
        """
        if not directory:
            temp_dir = tempfile.TemporaryDirectory(prefix='streamalert_build-')
            directory = temp_dir.name
            # Calling cleanup here to remove this directory so shutil can recreate it
            # Without calling this here, an exception is raised when tempfile garbage collects
            temp_dir.cleanup()


        if os.path.exists(directory):
            shutil.rmtree(directory)  # shutil.copytree in python3.7 cannot handle existing dir

        self._copy_terraform_files(directory)

        return directory

    def set_prefix(self, prefix):
        """Set the Org Prefix in Global settings"""
        if not isinstance(prefix, str):
            LOGGER.error('Invalid prefix type, must be string')
            return False

        acceptable_chars = {*string.digits, *string.ascii_lowercase}
        if not set(prefix).issubset(acceptable_chars):
            LOGGER.error('Prefix must contain only lowercase letters and numbers')
            return False

        self.config['global']['account']['prefix'] = prefix

        self.write()

        LOGGER.info('Prefix successfully configured')

        return True

    def set_aws_account_id(self, aws_account_id):
        """Set the AWS Account ID in Global settings"""
        if not re.search(r'\A\d{12}\Z', aws_account_id):
            LOGGER.error('Invalid AWS Account ID, must be 12 digits long')
            return False

        self.config['global']['account']['aws_account_id'] = aws_account_id
        self.write()

        LOGGER.info('AWS Account ID successfully configured')
        return True

    def toggle_rule_staging(self, enabled):
        """Toggle rule staging on or off

        Args:
            enabled (bool): False if disabling rule staging, true if enabling
        """
        print(f'Setting rule staging enabled setting to: {enabled}')
        self.config['global']['infrastructure']['rule_staging']['enabled'] = enabled
        self.write()

    def toggle_metrics(self, *lambda_functions, **kwargs):
        """Toggle CloudWatch metric logging and filter creation

        Args:
            enabled (bool): False if disabling metrics, true if enable_logging
            clusters (list): Clusters to enable or disable metrics on
            lambda_functions (list): Which lambda functions to enable or disable
                metrics on (rule, alert, or athena)
        """
        enabled = kwargs.get('enabled', False)
        clusters = kwargs.get('clusters', [])
        for function in lambda_functions:
            function_config = f'{function}_config'
            if function not in CLUSTERED_FUNCTIONS:
                if function_config not in self.config['lambda']:
                    self.config['lambda'][function_config] = {}
                self.config['lambda'][function_config]['enable_custom_metrics'] = enabled
            else:
                # Classifier - toggle for each cluster
                for cluster in clusters:
                    self.config['clusters'][cluster][function_config]['enable_custom_metrics'] = (
                        enabled)

        self.write()

    @staticmethod
    def _add_metric_alarm_config(alarm_info, current_alarms):
        """Helper function to add the metric alarm to the respective config

        Args:
            alarm_info (dict): All the necessary values needed to add a CloudWatch
                metric alarm
            current_alarms (dict): All of the current metric alarms from the config

        Returns:
            dict: The new metric alarms dictionary with the added metric alarm
        """
        # Some keys that come from the argparse options can be omitted
        omitted_keys = {'debug', 'alarm_name', 'command', 'clusters', 'function'}

        current_alarms[alarm_info['alarm_name']] = {
            key: value
            for key, value in alarm_info.items() if key not in omitted_keys
        }

        return current_alarms

    def _alarm_exists(self, alarm_name):
        """Check if this alarm name is already used somewhere. CloudWatch alarm
        names must be unique to an AWS account

        Args:
            alarm_name (str): The name of the alarm being created

        Returns:
            bool: True if the the alarm name is already present in the config
        """
        message = ('CloudWatch metric alarm names must be unique '
                   'within each AWS account. Please remove this alarm '
                   'so it can be updated or choose another name.')
        funcs = {metrics.CLASSIFIER_FUNCTION_NAME}
        for func in funcs:
            func_config = f'{func}_config'
            for cluster, cluster_config in self.config['clusters'].items():
                func_alarms = cluster_config[func_config].get('custom_metric_alarms', {})
                if alarm_name in func_alarms:
                    LOGGER.error(
                        'An alarm with name \'%s\' already exists in the '
                        '\'conf/clusters/%s.json\' cluster. %s', alarm_name, cluster, message)
                    return True

        for func, global_lambda_config in self.config['lambda'].items():
            if alarm_name in global_lambda_config.get('custom_metric_alarms', {}):
                LOGGER.error(
                    'An alarm with name \'%s\' already exists in the '
                    '\'conf/lambda.json\' in function config \'%s\'. %s', alarm_name, func, message)
                return True

        return False

    def _clusters_with_metrics_enabled(self, function):
        function_config = f'{function}_config'
        return {
            cluster
            for cluster, cluster_config in self.config['clusters'].items()
            if (self.config['clusters'][cluster][function_config].get('enable_custom_metrics'))
        }

    def _add_cluster_metric_alarm(self, alarm_info):
        """Add a metric alarm that corresponds to a predefined metrics for clusters

        Args:
            alarm_info (dict): All the necessary values needed to add a CloudWatch
                metric alarm.
        """
        function_name = alarm_info['function']

        # Go over each of the clusters and see if enable_metrics == True and prompt
        # the user to toggle metrics on if this is False
        config_name = f'{function_name}_config'
        for cluster in alarm_info['clusters']:
            function_config = (self.config['clusters'][cluster][config_name])

            if not function_config.get('enable_custom_metrics'):
                prompt = (
                    f"Metrics are not currently enabled for the '{function_name}' function within the '{cluster}' cluster. "
                    f"Would you like to enable metrics for this cluster?")
                if continue_prompt(message=prompt):
                    self.toggle_metrics(function_name, enabled=True, clusters=[cluster])

                elif not continue_prompt(message='Would you still like to add this alarm '
                                         'even though metrics are disabled?'):
                    continue

            metric_alarms = function_config.get('custom_metric_alarms', {})

            # Format the metric name for the cluster based metric
            # Prepend a prefix for this function and append the cluster name
            alarm_settings = alarm_info.copy()
            alarm_settings[
                'metric_name'] = f"{metrics.FUNC_PREFIXES[function_name]}-{alarm_settings['metric_name']}-{cluster.upper()}"

            function_config['custom_metric_alarms'] = self._add_metric_alarm_config(
                alarm_settings, metric_alarms)
            LOGGER.info(
                'Successfully added \'%s\' metric alarm for the \'%s\' '
                'function to \'conf/clusters/%s.json\'.', alarm_settings['alarm_name'],
                function_name, cluster)

        return True

    def _add_global_metric_alarm(self, alarm_info):
        """Add a metric alarm that corresponds to a predefined metrics globally

        Args:
            alarm_info (dict): All the necessary values needed to add a CloudWatch
                metric alarm
        """
        function_name = alarm_info['function']

        func_config_name = f'{function_name}_config'

        # Check if metrics are not enabled, and ask the user if they would like to enable them
        if func_config_name not in self.config['lambda']:
            self.config['lambda'][func_config_name] = {}

        function_config = self.config['lambda'][func_config_name]

        if function_name in CLUSTERED_FUNCTIONS:
            if not self._clusters_with_metrics_enabled(function_name):
                prompt = (
                    f"Metrics are not currently enabled for the \'{function_name}\' function within any cluster. Creating an alarm will "
                    f"have no effect until metrics are enabled for this function in at least one cluster. Would you still like to continue?"
                )

                if not continue_prompt(message=prompt):
                    return False

        elif not function_config.get('enable_custom_metrics'):
            prompt = (f"Metrics are not currently enabled for the \'{function_name}\' "
                      f"function. Would you like to enable metrics for this function?")

            if continue_prompt(message=prompt):
                self.toggle_metrics(function_name, enabled=True)

            elif not continue_prompt(message='Would you still like to add this alarm '
                                     'even though metrics are disabled?'):
                return False

        metric_alarms = function_config.get('custom_metric_alarms', {})

        # Format the metric name for the aggregate metric
        alarm_settings = alarm_info.copy()
        alarm_settings[
            'metric_name'] = f"{metrics.FUNC_PREFIXES[function_name]}-{alarm_settings['metric_name']}"

        function_config['custom_metric_alarms'] = self._add_metric_alarm_config(
            alarm_settings, metric_alarms)
        LOGGER.info('Successfully added \'%s\' metric alarm to '
                    '\'conf/lambda.json\'.', alarm_settings['alarm_name'])

        return True

    def add_metric_alarm(self, alarm_info):
        """Add a metric alarm that corresponds to a predefined metrics

        Args:
            alarm_info (dict): All the necessary values needed to add a CloudWatch
                metric alarm
        """
        # Check to see if an alarm with this name already exists
        if self._alarm_exists(alarm_info['alarm_name']):
            return False

        # Get the current metrics for each function
        current_metrics = metrics.MetricLogger.get_available_metrics()[alarm_info['function']]

        if alarm_info['metric_name'] not in current_metrics:
            LOGGER.error('Metric name \'%s\' not defined for function \'%s\'',
                         alarm_info['metric_name'], alarm_info['function'])
            return False

        if 'clusters' in alarm_info:
            self._add_cluster_metric_alarm(alarm_info)
        elif not self._add_global_metric_alarm(alarm_info):
            return False

        self.write()

        return True

    def add_app(self, func_name, app_info):
        """Add a configuration for a new streamalert app integration function

        Args:
            app_info (dict): The necessary values needed to begin configuring
                a new app integration

        Returns:
            bool: False if errors occurred, True otherwise
        """
        exists, prompt_for_auth, overwrite = False, True, False
        app = StreamAlertApp.get_app(app_info['type'])

        cluster_name = app_info['cluster']
        app_name = app_info['app_name']

        # Check to see if there is an existing configuration for this app integration
        cluster_config = self.config['clusters'][cluster_name]

        if func_name in cluster_config['modules'].get('streamalert_apps', {}):
            prompt = (
                f"An app with the name \'{app_name}\' is already configured for cluster \'{cluster_name}\'. "
                f"Would you like to update the existing app\'s configuration?")

            exists = True

            # Return if the user is not deliberately updating an existing config
            if not continue_prompt(message=prompt):
                return

            prompt = f"Would you also like to update the authentication information for app integration with name \'{app_name}\'?"

            # If this is true, we shouldn't prompt again to warn about overwriting
            prompt_for_auth = overwrite = continue_prompt(message=prompt)

        if prompt_for_auth and not save_app_auth_info(app, app_info, func_name, overwrite):
            return False

        apps_config = cluster_config['modules'].get('streamalert_apps', {})
        if not exists:
            # Save a default app settings to the config for new apps
            new_app_config = {
                'app_name': app_info['app_name'],
                'concurrency_limit': 2,
                'log_level': 'info',
                'log_retention_days': 14,
                'memory': app_info['memory'],
                'metric_alarms': {
                    'errors': {
                        'enabled': True,
                        'evaluation_periods': 1,
                        'period_secs': 120
                    }
                },
                'schedule_expression': app_info['schedule_expression'],
                'timeout': app_info['timeout'],
                'type': app_info['type']
            }
            apps_config[func_name] = new_app_config
        else:

            # Allow for updating certain attributes for the app without overwriting
            # current parts of the configuration
            updated_app_config = {
                'memory': app_info['memory'],
                'schedule_expression': app_info['schedule_expression'],
                'timeout': app_info['timeout']
            }
            apps_config[func_name].update(updated_app_config)

        cluster_config['modules']['streamalert_apps'] = apps_config

        # Add this service to the sources for this app integration
        # The `streamalert_app` is purposely singular here
        app_sources = self.config['clusters'][cluster_name]['data_sources'].get(
            'streamalert_app', {})
        app_sources[func_name] = [app.service()]
        self.config['clusters'][cluster_name]['data_sources']['streamalert_app'] = app_sources

        LOGGER.info(
            'Successfully added \'%s\' app integration to \'conf/clusters/%s.json\' '
            'for service \'%s\'.', app_info['app_name'], app_info['cluster'], app_info['type'])

        self.write()

        return True

    def add_threat_intel(self, threat_intel_info):
        """Add Threat Intel configure to config

        Args:
            threat_intel_info (dict): Settings to enable Threat Intel from commandline.
        """
        prefix = self.config['global']['account']['prefix']

        if 'threat_intel' not in self.config:
            self.config['threat_intel'] = {}

        self.config['threat_intel']['enabled'] = threat_intel_info['enable']

        if table_name := threat_intel_info.get('dynamodb_table_name'):
            self.config['threat_intel']['dynamodb_table_name'] = table_name
        elif not self.config['threat_intel'].get('dynamodb_table_name'):
            # set default dynamodb table name if one does not exist
            self.config['threat_intel'][
                'dynamodb_table_name'] = f'{prefix}_streamalert_threat_intel_downloader'

        self.write()

        LOGGER.info('Threat Intel configuration successfully created')

    def add_threat_intel_downloader(self, ti_downloader_info):
        """Add Threat Intel Downloader configure to config

        Args:
            ti_downloader_info (dict): Settings for Threat Intel Downloader Lambda
                function, generated from commandline
                "manage.py threat_intel_downloader enable"

        Returns:
            (bool): Return True if writing settings of Lambda function successfully.
        """
        default_config = {
            'autoscale': False,
            'enabled': True,
            'interval': 'rate(1 day)',
            'log_level': 'info',
            'memory': '128',
            'timeout': '120',
            'table_rcu': 10,
            'table_wcu': 10,
            'ioc_keys': [],
            'ioc_filters': [],
            'ioc_types': [],
            'excluded_sub_types': [],
            'max_read_capacity': 5,
            'min_read_capacity': 5,
            'target_utilization': 70
        }

        if 'threat_intel_downloader_config' in self.config['lambda']:
            LOGGER.info('Threat Intel Downloader has been enabled. '
                        'Please edit config/lambda.json if you want to '
                        'change lambda function settings.')
            return False

        self.config['lambda']['threat_intel_downloader_config'] = default_config
        # overwrite settings in conf/lambda.json for Threat Intel Downloader
        for key, value in ti_downloader_info.items():
            if key in self.config['lambda']['threat_intel_downloader_config']:
                self.config['lambda']['threat_intel_downloader_config'][key] = value

        self.write()
        return True

    @staticmethod
    def _config_writer(path, data, sort=False):
        with open(path, 'r+', encoding="utf-8") as conf_file:
            json.dump(data, conf_file, indent=2, separators=(',', ': '), sort_keys=sort)
            conf_file.truncate()

    def write(self):
        """Write the current config in memory to disk"""

        # Write loaded configuration files
        def format_path(parts):
            return f'{os.path.join(*parts)}.json'

        for config_key in self.config:
            path_parts = [self.config_path, config_key]
            if config_key == 'clusters':
                # Write loaded cluster files
                for cluster_key in self.config['clusters']:
                    parts = path_parts + [cluster_key]
                    self._config_writer(format_path(parts), self.config['clusters'][cluster_key])
            elif config_key != 'logs':
                self._config_writer(format_path(path_parts), self.config[config_key])
