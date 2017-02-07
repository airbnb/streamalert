import logging
import json
import os
import subprocess

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
            logging.error('Return Code %s - %s', e.returncode, e.cmd)
            return False

        return True

    @classmethod
    def update_config(cls, new_config):
        """Update variables.json with updated values.

        Args:
            new_config (dict): Loaded and updated variables.json dict

        """
        logging.info('Updating variables.json')
        with open('variables.json', 'w') as var_file:
            config_out = json.dumps(new_config,
                                    indent=4,
                                    separators=(',', ': '),
                                    sort_keys=True)
            var_file.write(config_out)
