import logging
import os
import subprocess

class CLIHelpers(object):
    @classmethod
    def run_command(cls, runner_args, **kwargs):
        """Helper function to run commands with error handling"""
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
        except (OSError, subprocess.CalledProcessError):
            logging.error('%s', error_message)
            return False

        return True
