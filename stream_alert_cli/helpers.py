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

import json
import os
import subprocess

from stream_alert_cli.logger import LOGGER_CLI

class CLIHelpers(object):
    """Common helpers between StreamAlert CLI classes"""
    @classmethod
    def run_command(cls, runner_args, **kwargs):
        """Helper function to run commands with error handling.

        Args:
            runner_args (list): Commands to run via subprocess
            kwargs:
                cwd (string): A path to execute commands from
                error_message (string): Message to show if command fails
                quiet (boolean): Whether to show command output or hide it

        """
        default_error_message = "An error occured while running: {}".format(
            ' '.join(runner_args)
        )
        error_message = kwargs.get('error_message', default_error_message)

        default_cwd = 'terraform'
        cwd = kwargs.get('cwd', default_cwd)

        stdout_option = None
        if kwargs.get('quiet'):
            stdout_option = open(os.devnull, 'w')

        try:
            subprocess.check_call(runner_args, stdout=stdout_option, cwd=cwd)
        except subprocess.CalledProcessError as e:
            LOGGER_CLI.error('Return Code %s - %s', e.returncode, e.cmd)
            return False

        return True
