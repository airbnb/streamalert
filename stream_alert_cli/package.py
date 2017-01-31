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

import base64
import hashlib
import zipfile
import json
import logging
import os
import tempfile

from datetime import datetime

import boto3

class LambdaPackage(object):
    """
    Build and upload the StreamAlert deployment package to S3.
    """
    packageFolders = ()
    packageFiles = ()
    packageName = None
    packageDir = None
    sourceKey = None
    sourceHashKey = None
    sourcePrefix = None

    def __init__(self, **kwargs):
        self.version = kwargs.get('version')
        self.config = kwargs.get('config')

    def create_and_upload(self):
        """
        Create a zip of the StreamAlert Lambda function,
        and then take its SHA256 hash.
        """
        temp_dir = self._get_tmpdir()
        pkg, pkg_path = self.zip(temp_dir)
        pkg_sha256, pkg_sha256_path = self._sha256sum(pkg_path)
        self._upload(temp_dir, pkg)
        self._cleanup([pkg_path, pkg_sha256_path])
        self._update_config(pkg, pkg_sha256)

    @staticmethod
    def _get_tmpdir():
        """
        Get a temporary directory to write files to.
        """
        return tempfile.gettempdir()

    @staticmethod
    def _cleanup(files):
        """
        Removes the temporary StreamAlert package and checksum.
        """
        logging.info('Removing local files')
        for obj in files:
            os.remove(obj)

    def _update_config(self, pkg, pkg_sha256):
        """
        Write generated deployment package filename and sha256 hash
        to `variables.json`.  We will need these values to deploy to production.
        """
        logging.info('Updating variables.json')
        with open('variables.json', 'r+') as varFile:
            config = json.load(varFile)
            config[self.sourceHashKey] = pkg_sha256
            config[self.sourceKey] = os.path.join(self.sourcePrefix, pkg)
            config_out = json.dumps(config, indent=4, separators=(',', ': '),
                                    sort_keys=True)
            varFile.seek(0)
            varFile.write(config_out)
            varFile.truncate()

    def zip(self, temp_dir):
        """
        Create the StreamAlert Lambda deployment package.
        Zips up all dependency files to run the function,
        and names the zip based on the current date/time,
        along with the declared version in __init__.py.

        example filename: stream_alert_1.0.0_20161010_00:11:22.zip

        Only package in the `.py` files per AWS's instructions
        for creation of lambda functions.

        Returns: Deployment package filename, and the
                 deployment package full path.
        """
        # Change dir into the folder with the lambda code
        startDir = os.getcwd()
        os.chdir(self.packageDir)

        # Set the date for the package name
        date = datetime.utcnow().strftime("%Y%m%d_T%H:%M:%S")
        basename = '_'.join([self.packageName, self.version, date])
        pkg = ''.join([basename, '.zip'])
        pkg_path = os.path.join(temp_dir, pkg)

        # Walk the package files/folders and add to archive
        logging.info('Creating Lambda package: %s', pkg)
        zf = zipfile.ZipFile(pkg_path, mode='w')
        for path in self.packageFolders:
            for root, _, files in os.walk(path):
                for packagefile in files:
                    if packagefile.endswith('.pyc'):
                        continue
                    arcname = os.path.join(root, packagefile)
                    zf.write(arcname)

        for packagefile in self.packageFiles:
            zf.write(packagefile)

        zf.close()
        logging.info('Package Successfully Created!')
        logging.debug('Wrote the following files to the deployment package: %s',
                      json.dumps(zf.namelist()))
        os.chdir(startDir)
        return pkg, pkg_path

    @staticmethod
    def _sha256sum(pkg_path):
        """
        After creating the deployment package, compute its SHA256
        hash.  This value is necessary to publish the staging
        lambda function to production.

        Returns: The checksum of the package passed and a path
                 to the file containing the checksum.
        """
        hasher = hashlib.sha256()
        with open(pkg_path, 'rb') as pkg_path_fh:
            hasher.update(pkg_path_fh.read())
            code_hash = hasher.digest()
            code_b64 = base64.b64encode(code_hash)
            pkg_sha256 = code_b64.decode('utf-8')

        pkg_sha256_path = pkg_path + '.sha256'
        with open(pkg_sha256_path, 'w') as pkg_sha256_path_fh:
            pkg_sha256_path_fh.write(pkg_sha256)

        return pkg_sha256, pkg_sha256_path

    def _upload(self, tempDir, package):
        """
        Upload the StreamAlert package and sha256 to S3.
        """
        logging.info('Uploading StreamAlert package to S3')
        client = boto3.client('s3', region_name=self.config['region'])
        for packageFile in (package, '{}.sha256'.format(package)):
            fh = open(os.path.join(tempDir, packageFile), 'r')
            try:
                client.put_object(
                    Bucket=self.config['lambda_source_bucket_name'],
                    Key=os.path.join(self.sourcePrefix, packageFile),
                    Body=fh,
                    ServerSideEncryption='AES256'
                )
            except:
                logging.info('An error occured while uploding %s', packageFile)
                raise
            fh.close()
            logging.info('Uploaded %s to S3', packageFile)

class AlertPackage(LambdaPackage):
    packageFolders = {'stream_alert', 'rules', 'conf'}
    packageFiles = {'main.py', 'variables.json'}
    packageDir = '.'
    packageName = 'stream_alert'
    sourceKey = 'lambda_source_key'
    sourceHashKey = 'lambda_source_current_hash'
    sourcePrefix = 'alert'

class OutputPackage(LambdaPackage):
    packageFolders = {'encrypted_credentials'}
    packageFiles = {'main.py'}
    packageDir = 'stream_alert_output'
    sourceKey = 'output_lambda_source_key'
    sourceHashKey = 'output_lambda_current_hash'
    packageName = 'stream_alert_output'
    sourcePrefix = 'output'
