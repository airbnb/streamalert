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

from stream_alert.shared.logger import get_logger
from stream_alert_cli.helpers import run_command

# Build .zip files in the top-level of the terraform directory
THIS_DIRECTORY = os.path.dirname(os.path.realpath(__file__))
BUILD_DIRECTORY = os.path.join(THIS_DIRECTORY, '..', '..', 'terraform')
LOGGER = get_logger(__name__)


class LambdaPackage(object):
    """Build a deployment package for a StreamAlert Lambda function."""
    config_key = None                  # Configuration key to access conf/lambda.json
    lambda_handler = None              # Entry point for the Lambda function
    package_files = set()              # The folders and files to zip into the Lambda package
    package_name = None                # The name of the generated .zip file
    precompiled_libs = set()           # Precompiled dependent libraries
    default_required_libs = {          # Default libraries to install into each package
        'backoff',
        'boto3',
    }
    package_libs = set()               # Libraries specifically needed for individual package(s)

    # Define a package dict to support pinning versions across all subclasses
    PACKAGE_LIBS = {
        'aliyun-python-sdk-actiontrail': 'aliyun-python-sdk-actiontrail==2.0.0',
        'backoff': 'backoff==1.8.0',
        'boto3': 'boto3==1.9.208',
        'boxsdk[jwt]': 'boxsdk[jwt]==2.0.0a11',
        'cbapi': 'cbapi==1.5.1',
        'google-api-python-client': 'google-api-python-client==1.6.4',
        'jmespath': 'jmespath==0.9.4',
        'jsonlines': 'jsonlines==1.2.0',
        'netaddr': 'netaddr==0.7.19',
        'oauth2client': 'oauth2client==4.1.3',
        'policyuniverse': 'policyuniverse==1.3.2.0',
        'requests': 'requests==2.22.0',
    }

    def __init__(self, config):
        self.config = config

    @property
    def _required_libs(self):
        return self.default_required_libs.union(self.package_libs)

    def create(self):
        """Create a Lambda deployment package .zip file."""
        LOGGER.info('Creating package for %s', self.package_name)

        temp_package_path = os.path.join(tempfile.gettempdir(), self.package_name)
        if os.path.exists(temp_package_path):
            shutil.rmtree(temp_package_path)

        self._copy_files(temp_package_path)

        if not self._resolve_libraries(temp_package_path):
            LOGGER.exception('Failed to install necessary libraries')
            exit(1)

        # Extract any precompiled libs for this package
        if self.precompiled_libs and not self._extract_precompiled_libs(temp_package_path):
            LOGGER.exception('Failed to extract precompiled libraries')
            exit(1)

        # Zip up files
        result = shutil.make_archive(
            os.path.join(BUILD_DIRECTORY, self.package_name), 'zip', temp_package_path)
        LOGGER.info('Successfully created %s', os.path.basename(result))

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
        """Extract any precompiled libraries into the deployment package folder

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
            libs_name = '_'.join([self.PACKAGE_LIBS[lib], 'dependencies.zip'])
            if libs_name not in dependency_files:
                LOGGER.error('Missing precompiled libs for package: %s', libs_name)
                return False

            # Copy the contents of the dependency zip to the package directory
            with zipfile.ZipFile(dependency_files[libs_name], 'r') as libs_file:
                libs_file.extractall(temp_package_path)

        return True

    def _resolve_libraries(self, temp_package_path):
        """Install all libraries into the deployment package folder

        Args:
            temp_package_path (str): Full path to temp package path

        Returns:
            bool: False if the pip command failed to install requirements, True otherwise
        """
        # Install all required core libs that were not precompiled for this package
        package_libs = self._required_libs.difference(self.precompiled_libs)

        libs_to_install = set()
        for item in package_libs:
            if item not in self.PACKAGE_LIBS:
                LOGGER.error(
                    'Please ensure a pinned version of package \'%s\' is included in PACKAGE_LIBS',
                    item
                )
                return False
            libs_to_install.add(self.PACKAGE_LIBS[item])

        # Add any custom libs needed by rules, etc
        if self.config_key in self.config['lambda']:
            libs_to_install.update(
                set(self.config['lambda'][self.config_key].get('third_party_libraries', [])))

        # Return a default of True here if no libraries to install
        if not libs_to_install:
            LOGGER.info('No libraries to install')
            return True

        LOGGER.info('Installing libraries: %s', ', '.join(libs_to_install))
        pip_command = ['pip', 'install']
        pip_command.extend(libs_to_install)
        pip_command.extend(['--upgrade', '--target', temp_package_path])

        # Return True if the pip command is successfully run
        return run_command(pip_command, cwd=temp_package_path, quiet=True)


class ClassifierPackage(LambdaPackage):
    """Deployment package class for the StreamAlert Classifier function"""
    config_key = 'classifier_config'
    lambda_handler = 'stream_alert.classifier.main.handler'
    package_files = {
        'conf',
        'stream_alert/__init__.py',
        'stream_alert/classifier',
        'stream_alert/shared',
    }
    package_name = 'classifier'
    package_libs = {'jmespath', 'jsonlines'}


class RulesEnginePackage(LambdaPackage):
    """Deployment package class for the StreamAlert Rules Engine function"""
    config_key = 'rules_engine_config'
    lambda_handler = 'stream_alert.rules_engine.main.handler'
    package_files = {
        'conf',
        'publishers',
        'rules',
        'stream_alert/__init__.py',
        'stream_alert/rules_engine',
        'stream_alert/shared',
    }
    package_name = 'rules_engine'
    package_libs = {'netaddr', 'policyuniverse'}


class AlertProcessorPackage(LambdaPackage):
    """Deployment package class for the StreamAlert Alert Processor function"""
    config_key = 'alert_processor_config'
    lambda_handler = 'stream_alert.alert_processor.main.handler'
    package_files = {
        'conf',
        'publishers',
        'stream_alert/__init__.py',
        'stream_alert/alert_processor',
        'stream_alert/shared'
    }
    package_name = 'alert_processor'
    package_libs = {'cbapi', 'netaddr', 'requests'}


class AlertMergerPackage(LambdaPackage):
    """Deployment package class for the StreamAlert Alert Merger function"""
    config_key = 'alert_merger_config'
    lambda_handler = 'stream_alert.alert_merger.main.handler'
    package_files = {
        'stream_alert/__init__.py',
        'stream_alert/alert_merger',
        'stream_alert/shared'
    }
    package_name = 'alert_merger'
    package_libs = {'netaddr'}


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
    precompiled_libs = {'boxsdk[jwt]', 'aliyun-python-sdk-actiontrail'}
    package_libs = {
        'aliyun-python-sdk-actiontrail',
        'backoff',
        'boxsdk[jwt]',
        'google-api-python-client',
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
    package_libs = {'requests'}


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
