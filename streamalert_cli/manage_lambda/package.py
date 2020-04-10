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
from streamalert_cli.terraform import TERRAFORM_FILES_PATH

LOGGER = get_logger(__name__)


class LambdaPackage:
    """Build the deployment package for StreamAlert Lambdas"""
    package_name = 'streamalert'       # The basename of the generated .zip file

    DEFAULT_PACKAGE_FILES = {          # The default folders to zip into the Lambda package
        'conf',
        'streamalert',
    }

    CONFIG_EXTRAS = {                  # The configurable items for user specified files
        'matcher_locations',
        'rule_locations',
        'scheduled_query_locations',
        'publisher_locations',
    }

    # Define a package dict to support pinning versions across all subclasses
    REQUIRED_LIBS = {
        'backoff==1.8.1',
        'boto3==1.10.6',
        'cbapi==1.5.4',
        'google-api-python-client==1.7.11',
        'jmespath==0.9.4',
        'jsonlines==1.2.0',
        'netaddr==0.7.19',
        'requests==2.22.0',
        'pymsteams==0.1.12',
    }

    def __init__(self, config):
        self.config = config
        self.temp_package_path = os.path.join(tempfile.gettempdir(), self.package_name)

    def _copy_user_config_files(self):
        paths = set()
        for location in self.CONFIG_EXTRAS:
            paths.update(self.config['global']['general'].get(location, set()))

        self._copy_files(paths, ignores={'*.json'})

    def create(self):
        """Create a Lambda deployment package .zip file."""
        LOGGER.info('Creating package for %s', self.package_name)

        if os.path.exists(self.temp_package_path):
            shutil.rmtree(self.temp_package_path)

        # Copy all of the default package files
        self._copy_files(self.DEFAULT_PACKAGE_FILES)

        # Copy in any user-specified files
        self._copy_user_config_files()

        if not self._resolve_libraries():
            LOGGER.error('Failed to install necessary libraries')
            return False

        # Zip it all up
        # Build these in the top-level of the terraform directory as streamalert.zip
        result = shutil.make_archive(
            os.path.join(TERRAFORM_FILES_PATH, self.package_name),
            'zip',
            self.temp_package_path
        )

        LOGGER.info('Successfully created package: %s', result)

        # Remove temp files
        shutil.rmtree(self.temp_package_path)

        return result

    def _copy_files(self, paths, ignores=None):
        """Copy all files and folders into temporary package path

        Args:
            paths (list): Paths of folders to be copied into the Lambda package
            ignores (set=None): File globs to be ignored during the copying of files in paths
        """
        for path in paths:
            # Copy the directory, skipping any files explicitly ignored
            kwargs = {'ignore': shutil.ignore_patterns(*ignores)} if ignores else dict()
            shutil.copytree(path, os.path.join(self.temp_package_path, path), **kwargs)

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
