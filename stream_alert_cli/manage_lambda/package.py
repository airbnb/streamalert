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

from app_integrations import __version__ as apps_version
from stream_alert import __version__ as stream_alert_version
from stream_alert.threat_intel_downloader import __version__ as ti_downloader_version
from stream_alert_cli.helpers import run_command
from stream_alert_cli.logger import LOGGER_CLI

# Build .zip files in the top-level of the terraform directory
THIS_DIRECTORY = os.path.dirname(os.path.realpath(__file__))
BUILD_DIRECTORY = os.path.join(THIS_DIRECTORY, '..', '..', 'terraform')


class LambdaPackage(object):
    """Build and upload a StreamAlert deployment package to S3.

    Class Variables:
        package_folders (set): The folders to zip into the Lambda package
        package_files (set): The set of files to add to the Lambda package
        package_name (str): The name of the zip file to put on S3
        package_root_dir (str): Working directory to begin the zip
        config_key (str): The configuration key to update after creation
    """
    config_key = None
    package_folders = set()
    package_files = set()
    package_name = None
    package_root_dir = '.'
    precompiled_libs = set()
    third_party_libs = set()
    version = None

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
        if not self._extract_precompiled_libs(temp_package_path):
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
        for package_folder in self.package_folders:
            # Skip copying any files with a 'dependencies.zip' suffix
            shutil.copytree(
                os.path.join(self.package_root_dir, package_folder),
                os.path.join(temp_package_path, package_folder),
                ignore=shutil.ignore_patterns(*{'*dependencies.zip'}))

        for package_file in self.package_files:
            shutil.copy(
                os.path.join(self.package_root_dir, package_file),
                os.path.join(temp_package_path, package_file))

    def _extract_precompiled_libs(self, temp_package_path):
        """Extract any precompiled third-party packages into the deployment package folder

        Args:
            temp_package_path (str): Full path to temp package path

        Returns:
            bool: False if the required libs were not found, True if otherwise
        """
        # Return true immediately if there are no precompiled requirements for this package
        if not self.precompiled_libs:
            return True

        # Get any dependency files throughout the package folders that have
        # the _dependencies.zip suffix
        dependency_files = {
            package_file: os.path.join(root, package_file)
            for folder in self.package_folders for root, _, package_files in os.walk(folder)
            for package_file in package_files if package_file.endswith('_dependencies.zip')
        }

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


class RuleProcessorPackage(LambdaPackage):
    """Deployment package class for the StreamAlert Rule Processor function"""
    config_key = 'rule_processor_config'
    package_folders = {
        'stream_alert/rule_processor', 'stream_alert/shared', 'rules', 'matchers', 'helpers', 'conf'
    }
    package_files = {'stream_alert/__init__.py'}
    package_name = 'rule_processor'
    third_party_libs = {'backoff', 'netaddr', 'jsonpath_rw'}
    version = stream_alert_version


class AlertProcessorPackage(LambdaPackage):
    """Deployment package class for the StreamAlert Alert Processor function"""
    package_folders = {'stream_alert/alert_processor', 'stream_alert/shared', 'conf', 'helpers'}
    package_files = {'stream_alert/__init__.py'}
    package_name = 'alert_processor'
    config_key = 'alert_processor_config'
    third_party_libs = {'backoff', 'cbapi', 'netaddr', 'requests'}
    version = stream_alert_version


class AlertMergerPackage(LambdaPackage):
    """Deployment package class for the StreamAlert Alert Merger function"""
    package_folders = {'stream_alert/alert_merger', 'stream_alert/shared', 'conf', 'helpers'}
    package_files = {'stream_alert/__init__.py'}
    package_name = 'alert_merger'
    config_key = 'alert_merger_config'
    third_party_libs = {'backoff', 'netaddr'}
    version = stream_alert_version


class AppIntegrationPackage(LambdaPackage):
    """Deployment package class for App integration functions"""
    package_folders = {'app_integrations'}
    package_files = {'app_integrations/__init__.py'}
    package_name = 'stream_alert_app'
    config_key = 'stream_alert_apps_config'
    third_party_libs = {
        'backoff',
        'boxsdk[jwt]==2.0.0a11',
        'google-api-python-client==1.6.4',
        'oauth2client',
        'requests'
    }
    precompiled_libs = {'boxsdk[jwt]==2.0.0a11'}
    version = apps_version


class AthenaPackage(LambdaPackage):
    """Create the Athena Partition Refresh Lambda function package"""
    package_folders = {'stream_alert/athena_partition_refresh', 'stream_alert/shared', 'conf'}
    package_files = {'stream_alert/__init__.py'}
    package_name = 'athena_partition_refresh'
    config_key = 'athena_partition_refresh_config'
    third_party_libs = {'backoff'}
    version = stream_alert_version


class ThreatIntelDownloaderPackage(LambdaPackage):
    """Create the Threat Intel Downloader Lambda function package"""
    package_folders = {'stream_alert/threat_intel_downloader', 'stream_alert/shared', 'conf'}
    package_files = {'stream_alert/__init__.py'}
    package_name = 'threat_intel_downloader'
    config_key = 'threat_intel_downloader_config'
    third_party_libs = {'backoff', 'requests'}
    version = ti_downloader_version
