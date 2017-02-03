'''
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
'''

from datetime import datetime

import base64
import hashlib
import logging
import os
import shutil
import tempfile
import pip

from stream_alert_cli.helpers import CLIHelpers

import boto3

class LambdaPackage(object):
    """Build and upload a StreamAlert deployment package to S3."""
    package_folders = ()
    package_files = ()
    package_name = None
    package_root_dir = None
    source_key = None
    source_hash_key = None
    source_prefix = None

    def __init__(self, **kwargs):
        self.version = kwargs['version']
        self.config = kwargs['config']

    def create_and_upload(self):
        """Create a Lambda deployment package, checksum it, and upload it to S3.

        Reference:
            package_name: Generated name based on date/time/version/name
            temp_package_path: Temp package to store deployment package files
            package_path: Full path to zipped deployment package
            package_sha256: Checksum of package_path
            package_sha256_path: Full path to package_path checksum file
        """
        # get tmp dir and copy files
        temp_package_path = self._get_tmpdir()
        self._copy_files(temp_package_path)
        # download third-party libs
        self._resolve_third_party(temp_package_path)
        # zip up files
        package_path = self.zip(temp_package_path)
        package_name = package_path.split('/')[-1]
        # checksum files
        package_sha256, package_sha256_path = self._sha256sum(package_path)
        # upload to s3
        if self._upload(package_path):
            # remove generated deployment files
            self._cleanup(package_path, package_sha256_path)
            # set new config values and update
            self.config[self.source_key] = os.path.join(self.source_prefix,
                                                        package_name)
            self.config[self.source_hash_key] = package_sha256
            CLIHelpers.update_config(self.config)

    def _get_tmpdir(self):
        """Return a temporary directory to write files to.

        Example: tmpfolder/stream_alert_1.0.0_date_time/
        """
        date = datetime.utcnow().strftime("%Y%m%d_T%H%M%S")
        package_name = '_'.join([self.package_name, self.version, date])
        temp_package_path = os.path.join(tempfile.gettempdir(), package_name)
        return temp_package_path

    @staticmethod
    def _cleanup(*files):
        """Removes the temporary StreamAlert package and checksum.

        Args:
            files (tuple): full filepaths to cleanup after uploading to S3.
        """
        logging.info('Removing local files')
        for obj in files:
            os.remove(obj)

    def _copy_files(self, temp_package_path):
        """Copy all files and folders into temporary package path"""
        for package_folder in self.package_folders:
            shutil.copytree(os.path.join(self.package_root_dir, package_folder),
                            os.path.join(temp_package_path, package_folder))

        for package_file in self.package_files:
            shutil.copy(os.path.join(self.package_root_dir, package_file),
                        os.path.join(temp_package_path, package_file))

    @staticmethod
    def zip(temp_package_path):
        """Create the StreamAlert Lambda deployment package archive.

        Zips up all dependency files to run the function,
        and names the zip based on the current date/time,
        along with the declared version in __init__.py.

            example filename: stream_alert_1.0.0_20161010_00:11:22.zip

            Only package in the `.py` files per AWS's instructions
            for creation of lambda functions.

        Args:
            temp_package_path (string): the temporary file path to store the zip.

        Returns:
            Deployment package filename
            Deployment package full path
        """
        logging.info('Creating Lambda package: %s', ''.join([temp_package_path, '.zip']))
        package_path = shutil.make_archive(temp_package_path, 'zip', temp_package_path)
        logging.info('Package Successfully Created!')

        return package_path

    @staticmethod
    def _sha256sum(package_path):
        """Take a SHA256 checksum of a deployment package

        After creating the deployment package, compute its SHA256
        hash.  This value is necessary to publish the `staging`
        AWS Lambda function to `production`.

        Args:
            package_path (string): Full path to our zipped deployment package

        Returns:
            The generated SHA256 checksum of the package
            A path to the checksum file
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

        Note: For Mac OSX/Homebrew users, add the following to ~/.pydistutils.cfg:
              [install]
              prefix=

        Args:
            temp_package_path (string): Full path to temp package path

        """
        third_party_libs = self.config.get('third_party_libs')
        if third_party_libs:
            if len(third_party_libs) > 0:
                logging.info('Installing third-party libraries')
                pip_command = ['install']
                pip_command.extend(third_party_libs)
                pip_command.extend(['--upgrade', '--target', temp_package_path])
                pip.main(pip_command)
            else:
                logging.info('No third-party libraries to install.')

    def _upload(self, package_path):
        """Upload the StreamAlert package and sha256 to S3."""
        logging.info('Uploading StreamAlert package to S3')
        client = boto3.client('s3', region_name=self.config['region'])
        # the zip and the checksum file
        for package_file in (package_path, '{}.sha256'.format(package_path)):
            package_name = package_file.split('/')[-1]
            package_fh = open(package_file, 'r')
            try:
                client.put_object(
                    Bucket=self.config['lambda_source_bucket_name'],
                    Key=os.path.join(self.source_prefix, package_name),
                    Body=package_fh,
                    ServerSideEncryption='AES256'
                )
            except:
                logging.info('An error occured while uploding %s', package_name)
                raise
            package_fh.close()
            logging.info('Uploaded %s to S3', package_name)

        return True

class AlertPackage(LambdaPackage):
    """Deployment package class for the AWS Lambda `Alert` function"""
    package_folders = {'stream_alert', 'rules', 'conf'}
    package_files = {'main.py', 'variables.json'}
    package_root_dir = '.'
    package_name = 'stream_alert'

    source_key = 'lambda_source_key'
    source_hash_key = 'lambda_source_current_hash'
    source_prefix = 'alert'

class OutputPackage(LambdaPackage):
    """Deployment package class for the AWS Lambda `Output` function"""
    package_folders = {'encrypted_credentials'}
    package_files = {'main.py'}
    package_root_dir = 'stream_alert_output'
    package_name = 'stream_alert_output'

    source_key = 'output_lambda_source_key'
    source_hash_key = 'output_lambda_current_hash'
    source_prefix = 'output'
