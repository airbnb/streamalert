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
import os
import shutil
import tempfile

from streamalert.shared.logger import get_logger
from streamalert_cli.helpers import run_command

LOGGER = get_logger(__name__)


class LambdaPackage:
    """Build the deployment package for StreamAlert Lambdas"""
    # The name of the directory to package and basename of the generated .zip file
    PACKAGE_NAME = 'streamalert'

    # The configurable items for user specified files to include in deployment pacakge
    CONFIG_EXTRAS = {
        'matcher_locations',
        'rule_locations',
        'scheduled_query_locations',
        'publisher_locations',
    }

    # Define a package dict to support pinning versions across all subclasses
    REQUIRED_LIBS = {
        'backoff==1.10.0',
        'boto3==1.14.29',
        'cbapi==1.7.1',
        'google-api-python-client==1.10.0',
        'jmespath==0.10.0',
        'jsonlines==1.2.0',
        'netaddr==0.8.0',
        'requests==2.24.0',
        'pymsteams==0.1.13',
    }

    def __init__(self, config):
        self.config = config
        self.temp_package_path = os.path.join(tempfile.gettempdir(), self.PACKAGE_NAME)

    def _copy_user_config_files(self):
        for location in self.CONFIG_EXTRAS:
            paths = self.config['global']['general'].get(location, set())
            if not paths:
                continue
            for path in paths:
                self._copy_directory(path, ignores={'*.json'})

    def create(self):
        """Create a Lambda deployment package .zip file."""
        LOGGER.info('Creating package for %s', self.PACKAGE_NAME)

        if os.path.exists(self.temp_package_path):
            shutil.rmtree(self.temp_package_path)

        # Copy the default package directory
        self._copy_directory(self.PACKAGE_NAME)

        # Copy the user-specified config directory
        # Ensure this is copied to the 'conf' destination directory
        self._copy_directory(self.config.config_path, destination='conf')

        # Copy in any user-specified files
        self._copy_user_config_files()

        if not self._resolve_libraries():
            LOGGER.error('Failed to install necessary libraries')
            return False

        # Zip it all up
        # Build these in the top-level of the terraform directory as streamalert.zip
        result = shutil.make_archive(
            os.path.join(self.config.build_directory, self.PACKAGE_NAME),
            'zip',
            self.temp_package_path
        )

        LOGGER.info('Successfully created package: %s', result)

        # Remove temp files
        shutil.rmtree(self.temp_package_path)

        return result

    def _copy_directory(self, path, ignores=None, destination=None):
        """Copy all files and folders into temporary package path

        Args:
            path (str): Path of directory to be copied into the Lambda package
            ignores (set=None): File globs to be ignored during the copying of the directory
        """
        # Copy the directory, skipping any files explicitly ignored
        kwargs = {'ignore': shutil.ignore_patterns(*ignores)} if ignores else dict()
        destination = destination or path
        destination = os.path.join(self.temp_package_path, destination)
        shutil.copytree(path, destination, **kwargs)

    def _resolve_libraries(self):
        """Install all libraries into the deployment package folder

        Returns:
            bool: False if the pip command failed to install requirements, True otherwise
        """
        # Merge any custom libs needed by rules, etc
        libs_to_install = self.REQUIRED_LIBS.union(
            set(self.config['global']['general'].get('third_party_libraries', []))
        )

        LOGGER.info('Installing libraries: %s', ', '.join(libs_to_install))
        pip_command = ['pip', 'install']
        pip_command.extend(libs_to_install)
        pip_command.extend(['--no-cache-dir', '--upgrade', '--target', self.temp_package_path])

        # Return True if the pip command is successfully run
        return run_command(pip_command, cwd=self.temp_package_path, quiet=True)
