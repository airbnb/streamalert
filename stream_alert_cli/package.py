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
import base64
from datetime import datetime
import hashlib
import os
import shutil
import tempfile

import boto3
from botocore.exceptions import ClientError

from stream_alert_cli.helpers import run_command
from stream_alert_cli.logger import LOGGER_CLI


class LambdaPackage(object):
    """Build and upload a StreamAlert deployment package to S3.

    Class Variables:
        package_folders (set): The folders to zip into the Lambda package
        package_files (set): The set of files to add to the Lambda package
        package_name (str): The name of the zip file to put on S3
        package_root_dir (str): Working directory to begin the zip
        config_key (str): The configuration key to update after creation
    """
    package_folders = set()
    package_files = set()
    package_name = None
    package_root_dir = None
    config_key = None

    def __init__(self, **kwargs):
        self.version = kwargs['version']
        self.config = kwargs['config']

    def create_and_upload(self):
        """Create a Lambda deployment package, hash it, and upload it to S3.

        Reference:
            package_name: Generated name based on date/time/version/name
            temp_package_path: Temp package to store deployment package files
            package_path: Full path to zipped deployment package
            package_sha256: Checksum of package_path
            package_sha256_path: Full path to package_path checksum file
        """
        LOGGER_CLI.info('Creating package for %s', self.package_name)
        # get tmp dir and copy files
        temp_package_path = self._get_tmpdir()
        self._copy_files(temp_package_path)
        # download third-party libs
        if not self._resolve_third_party(temp_package_path):
            LOGGER_CLI.exception('Failed to install necessary third-party libraries')
            exit(1)

        # zip up files
        package_path = self.zip(temp_package_path)
        generated_package_name = package_path.split('/')[-1]
        # checksum files
        package_sha256, package_sha256_path = self._sha256sum(package_path)
        # upload to s3
        if self._upload(package_path):
            # remove generated deployment files
            self._cleanup(package_path, package_sha256_path)
            # set new config values and update
            full_package_name = os.path.join(self.package_name, generated_package_name)
            # make all config changes here
            self.config['lambda'][self.config_key]['source_object_key'] = full_package_name
            self.config['lambda'][self.config_key]['source_current_hash'] = package_sha256
            self.config.write()

    def _get_tmpdir(self):
        """Generate a temporary directory and package name

        Returns:
            str: A temp directory to write files to, e.g. tmpfolder/rule_processor_1.0.0_date_time/
        """
        date = datetime.utcnow().strftime("%Y%m%d_T%H%M%S")
        package_name = '_'.join([self.package_name, self.version, date])
        temp_package_path = os.path.join(tempfile.gettempdir(), package_name)
        return temp_package_path

    @staticmethod
    def _cleanup(*files):
        """Removes the temporary StreamAlert package and checksum.

        Args:
            files (str): File paths to remove after uploading to S3.
        """
        LOGGER_CLI.debug('Removing local files')
        for obj in files:
            os.remove(obj)

    def _copy_files(self, temp_package_path):
        """Copy all files and folders into temporary package path."""
        for package_folder in self.package_folders:
            shutil.copytree(os.path.join(self.package_root_dir, package_folder),
                            os.path.join(temp_package_path, package_folder))

        for package_file in self.package_files:
            shutil.copy(os.path.join(self.package_root_dir, package_file),
                        os.path.join(temp_package_path, package_file))

    @staticmethod
    def zip(temp_package_path):
        """Create the StreamAlert Lambda deployment package archive.

        Zips all dependency files to run the function,
        and names this zipfile based on the current date/time,
        along with the Lambda function module version.

            example filename: stream_alert_1.0.0_20161010_00:11:22.zip

            Only package in the `.py` files per AWS's instructions
            for creation of lambda functions.

        Args:
            temp_package_path (str): the temporary file path to store the zip.

        Returns:
            str: Deployment package full path
        """
        LOGGER_CLI.debug('Creating Lambda package: %s', temp_package_path + '.zip')
        package_path = shutil.make_archive(temp_package_path, 'zip', temp_package_path)
        LOGGER_CLI.info('Package successfully created')

        return package_path

    @staticmethod
    def _sha256sum(package_path):
        """Take a SHA256 checksum of a deployment package

        After creating the deployment package, compute its SHA256
        hash.  This value is necessary to publish the `staging`
        AWS Lambda function to `production`.

        Args:
            package_path (str): Full path to our zipped deployment package

        Returns:
            str, str: SHA256 checksum of the package, checksum file path
        """
        hasher = hashlib.sha256()
        with open(package_path, 'rb') as package_fh:
            hasher.update(package_fh.read())
            code_hash = hasher.digest()
            code_b64 = base64.b64encode(code_hash)
            package_sha256 = code_b64.decode('utf-8')

        package_sha256_path = package_path + '.sha256'
        with open(package_sha256_path, 'w') as package_sha256_fh:
            package_sha256_fh.write(package_sha256)

        return package_sha256, package_sha256_path

    def _resolve_third_party(self, temp_package_path):
        """Install all third-party packages into the deployment package folder

        Args:
            temp_package_path (str): Full path to temp package path

        Returns:
            bool: False if the pip command failed to install requirements, True otherwise
        """
        third_party_libs = self.config['lambda'][self.config_key]['third_party_libraries']
        # Return a default of True here if no libraries to install
        if not third_party_libs:
            LOGGER_CLI.info('No third-party libraries to install.')
            return True

        LOGGER_CLI.info(
            'Installing third-party libraries: %s',
            ', '.join(third_party_libs))
        pip_command = ['pip', 'install']
        pip_command.extend(third_party_libs)
        pip_command.extend(['--upgrade', '--target', temp_package_path])

        # Return True if the pip command is successfully run
        return run_command(pip_command, cwd=temp_package_path, quiet=True)

    def _upload(self, package_path):
        """Upload the StreamAlert package and sha256 sum to S3.

        Args:
            package path (str): Full path to the zipped dpeloyment package

        Returns:
            bool: Indicating a successful S3 upload
        """
        LOGGER_CLI.info('Uploading StreamAlert package to S3')
        client = boto3.client(
            's3', region_name=self.config['global']['account']['region'])

        for package_file in (package_path, '{}.sha256'.format(package_path)):
            package_name = package_file.split('/')[-1]
            package_fh = open(package_file, 'r')

            try:
                client.put_object(
                    Bucket=self.config['lambda'][self.config_key]['source_bucket'],
                    Key=os.path.join(self.package_name, package_name),
                    Body=package_fh,
                    ServerSideEncryption='AES256'
                )
            except ClientError:
                LOGGER_CLI.exception('An error occurred while uploading %s', package_name)
                return False

            package_fh.close()
            LOGGER_CLI.debug('Uploaded %s to S3', package_name)

        return True


class RuleProcessorPackage(LambdaPackage):
    """Deployment package class for the StreamAlert Rule Processor function"""
    package_folders = {
        'stream_alert/rule_processor',
        'stream_alert/shared',
        'rules',
        'matchers',
        'helpers',
        'conf'}
    if os.path.exists('threat_intel'):
        package_folders.add('threat_intel')
    package_files = {'stream_alert/__init__.py'}
    package_root_dir = '.'
    package_name = 'rule_processor'
    config_key = 'rule_processor_config'


class AlertProcessorPackage(LambdaPackage):
    """Deployment package class for the StreamAlert Alert Processor function"""
    package_folders = {
        'stream_alert/alert_processor',
        'stream_alert/shared',
        'conf'}
    package_files = {'stream_alert/__init__.py'}
    package_root_dir = '.'
    package_name = 'alert_processor'
    config_key = 'alert_processor_config'


class AppIntegrationPackage(LambdaPackage):
    """Deployment package class for App integration functions"""
    package_folders = {'app_integrations'}
    package_files = {'app_integrations/__init__.py'}
    package_root_dir = '.'
    package_name = 'stream_alert_app'
    config_key = 'stream_alert_apps_config'


class AthenaPackage(LambdaPackage):
    """Create the Athena Partition Refresh Lambda function package"""
    package_folders = {
        'stream_alert/athena_partition_refresh',
        'stream_alert/shared',
        'conf'}
    package_files = {'stream_alert/__init__.py'}
    package_root_dir = '.'
    package_name = 'athena_partition_refresh'
    config_key = 'athena_partition_refresh_config'
