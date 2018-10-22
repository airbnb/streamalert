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
import os
import shutil
import tempfile
import zipfile

from stream_alert_cli.helpers import run_command
from stream_alert_cli.logger import LOGGER_CLI

# Build .zip files in the top-level of the terraform directory
THIS_DIRECTORY = os.path.dirname(os.path.realpath(__file__))
BUILD_DIRECTORY = os.path.join(THIS_DIRECTORY, '..', '..', 'terraform')


class LambdaPackage(object):
    """Build a deployment package for a StreamAlert Lambda function."""
    config_key = None         # Configuration key to access conf/lambda.json
    lambda_handler = None     # Entry point for the Lambda function
    package_files = set()     # The folders and files to zip into the Lambda package
    package_name = None       # The name of the generated .zip file
    precompiled_libs = set()  # Precompiled dependent libraries
    third_party_libs = set()  # Pip libraries to install into each package

    def __init__(self, config):
        self.config = config

    def create(self):
        """Create a Lambda deployment package .zip file."""
        LOGGER_CLI.info('Creating package for %s', self.package_name)

        temp_package_path = os.path.join(tempfile.gettempdir(), self.package_name)
        if os.path.exists(temp_package_path):
            shutil.rmtree(temp_package_path)

        self._copy_files(temp_package_path)

        if not self._resolve_third_party(temp_package_path):
            LOGGER_CLI.exception('Failed to install necessary third-party libraries')
            exit(1)

        # Extract any precompiled third-party libs for this package
        if self.precompiled_libs and not self._extract_precompiled_libs(temp_package_path):
            LOGGER_CLI.exception('Failed to extract precompiled third-party libraries')
            exit(1)

        # Zip up files
        result = shutil.make_archive(
            os.path.join(BUILD_DIRECTORY, self.package_name), 'zip', temp_package_path)
        LOGGER_CLI.info('Successfully created %s', os.path.basename(result))

        # Remove temp files
        shutil.rmtree(temp_package_path)

        return True

    def _copy_files(self, temp_package_path):
        """Copy all files and folders into temporary package path."""
        for path in self.package_files:
            if os.path.isdir(path):
                # Copy the directory, skipping any files with a 'dependencies.zip' suffix
                shutil.copytree(
                    path, os.path.join(temp_package_path, path),
                    ignore=shutil.ignore_patterns(*{'*dependencies.zip'})
                )
            else:
                # Ensure the parent directory of the file being copied already exists
                copy_to_full_path = os.path.join(temp_package_path, path)
                dir_of_file_dest = os.path.dirname(copy_to_full_path)
                if not os.path.exists(dir_of_file_dest):
                    os.makedirs(dir_of_file_dest)
                shutil.copy(path, copy_to_full_path)

    def _extract_precompiled_libs(self, temp_package_path):
        """Extract any precompiled third-party packages into the deployment package folder

        Args:
            temp_package_path (str): Full path to temp package path

        Returns:
            bool: True if precompiled libs were extracted successfully, False if some are missing
        """
        dependency_files = {}  # Map library name to location of its precompiled .zip file
        for path in self.package_files:
            if path.endswith('_dependencies.zip'):
                dependency_files[os.path.basename(path)] = path
            elif os.path.isdir(path):
                # Traverse directory looking for .zip files
                for root, _, package_files in os.walk(path):
                    dependency_files.update({
                        package_file: os.path.join(root, package_file)
                        for package_file in package_files
                        if package_file.endswith('_dependencies.zip')
                    })

        for lib in self.precompiled_libs:
            libs_name = '_'.join([lib, 'dependencies.zip'])
            if libs_name not in dependency_files:
                LOGGER_CLI.error('Missing precompiled libs for package: %s', libs_name)
                return False

            # Copy the contents of the dependency zip to the package directory
            with zipfile.ZipFile(dependency_files[libs_name], 'r') as libs_file:
                libs_file.extractall(temp_package_path)

        return True

    def _resolve_third_party(self, temp_package_path):
        """Install all third-party packages into the deployment package folder

        Args:
            temp_package_path (str): Full path to temp package path

        Returns:
            bool: False if the pip command failed to install requirements, True otherwise
        """
        # Install all required core libs that were not precompiled for this package
        third_party_libs = self.third_party_libs.difference(self.precompiled_libs)

        # Add any custom libs needed by rules, etc
        if self.config_key in self.config['lambda']:
            third_party_libs.update(
                set(self.config['lambda'][self.config_key].get('third_party_libraries', [])))

        # Return a default of True here if no libraries to install
        if not third_party_libs:
            LOGGER_CLI.info('No third-party libraries to install.')
            return True

        LOGGER_CLI.info('Installing third-party libraries: %s', ', '.join(third_party_libs))
        pip_command = ['pip', 'install']
        pip_command.extend(third_party_libs)
        pip_command.extend(['--upgrade', '--target', temp_package_path])

        # Return True if the pip command is successfully run
        return run_command(pip_command, cwd=temp_package_path, quiet=True)


class ClassifierPackage(LambdaPackage):
    """Deployment package class for the StreamAlert Classifier function"""
    config_key = 'classifier_config'
    lambda_handler = 'stream_alert.classifier.main.handler'
    package_files = {
        'conf',
        'rules',
        'stream_alert/__init__.py',
        'stream_alert/classifier',
        'stream_alert/shared',
    }
    package_name = 'classifier'
    third_party_libs = {'backoff', 'jmespath', 'jsonlines'}


class RuleProcessorPackage(LambdaPackage):
    """Deployment package class for the StreamAlert Rule Processor function"""
    config_key = 'rule_processor_config'
    lambda_handler = 'stream_alert.rule_processor.main.handler'
    package_files = {
        'conf',
        'helpers',
        'matchers',
        'rules',
        'stream_alert/__init__.py',
        'stream_alert/rule_processor',
        'stream_alert/shared',
    }
    package_name = 'rule_processor'
    third_party_libs = {'backoff', 'netaddr', 'jsonpath_rw'}


class RulesEnginePackage(LambdaPackage):
    """Deployment package class for the StreamAlert Rules Engine function"""
    config_key = 'rules_engine_config'
    lambda_handler = 'stream_alert.rules_engine.main.handler'
    package_files = {
        'conf',
        'helpers',
        'matchers',
        'rules',
        'stream_alert/__init__.py',
        'stream_alert/rules_engine',
        'stream_alert/shared',
    }
    package_name = 'rules_engine'
    third_party_libs = {'backoff', 'netaddr'}


class AlertProcessorPackage(LambdaPackage):
    """Deployment package class for the StreamAlert Alert Processor function"""
    config_key = 'alert_processor_config'
    lambda_handler = 'stream_alert.alert_processor.main.handler'
    package_files = {
        'conf',
        'helpers',
        'stream_alert/__init__.py',
        'stream_alert/alert_processor',
        'stream_alert/shared'
    }
    package_name = 'alert_processor'
    third_party_libs = {'backoff', 'cbapi', 'netaddr', 'requests'}


class AlertMergerPackage(LambdaPackage):
    """Deployment package class for the StreamAlert Alert Merger function"""
    config_key = 'alert_merger_config'
    lambda_handler = 'stream_alert.alert_merger.main.handler'
    package_files = {
        'conf',
        'helpers',
        'stream_alert/__init__.py',
        'stream_alert/alert_merger',
        'stream_alert/shared'
    }
    package_name = 'alert_merger'
    third_party_libs = {'backoff', 'netaddr'}


class AppPackage(LambdaPackage):
    """Deployment package class for App functions"""
    config_key = 'stream_alert_apps_config'
    lambda_handler = 'stream_alert.apps.main.handler'
    package_files = {
        'stream_alert/__init__.py',
        'stream_alert/apps',
        'stream_alert/shared'
    }
    package_name = 'stream_alert_app'
    precompiled_libs = {'boxsdk[jwt]==2.0.0a11', 'aliyun-python-sdk-actiontrail==2.0.0'}
    third_party_libs = {
        'aliyun-python-sdk-actiontrail==2.0.0',
        'backoff',
        'boxsdk[jwt]==2.0.0a11',
        'google-api-python-client==1.6.4',
        'oauth2client',
        'requests'
    }


class AthenaPackage(LambdaPackage):
    """Create the Athena Partition Refresh Lambda function package"""
    config_key = 'athena_partition_refresh_config'
    lambda_handler = 'stream_alert.athena_partition_refresh.main.handler'
    package_files = {
        'conf',
        'stream_alert/__init__.py',
        'stream_alert/athena_partition_refresh',
        'stream_alert/shared'
    }
    package_name = 'athena_partition_refresh'
    third_party_libs = {'backoff'}


class ThreatIntelDownloaderPackage(LambdaPackage):
    """Create the Threat Intel Downloader Lambda function package"""
    config_key = 'threat_intel_downloader_config'
    lambda_handler = 'stream_alert.threat_intel_downloader.main.handler'
    package_files = {
        'conf',
        'stream_alert/__init__.py',
        'stream_alert/shared',
        'stream_alert/threat_intel_downloader'
    }
    package_name = 'threat_intel_downloader'
    third_party_libs = {'backoff', 'requests'}


class RulePromotionPackage(LambdaPackage):
    """Deployment package class for the StreamAlert Rule Promotion function"""
    config_key = 'rule_promotion_config'
    lambda_handler = 'stream_alert.rule_promotion.main.handler'
    package_files = {
        'conf',
        'stream_alert/__init__.py',
        'stream_alert/rule_promotion',
        'stream_alert/shared'
    }
    package_name = 'rule_promotion'
    third_party_libs = {'backoff'}
