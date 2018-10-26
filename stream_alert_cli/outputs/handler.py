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
from stream_alert.alert_processor.outputs.output_base import StreamAlertOutput
from stream_alert_cli.helpers import user_input
from stream_alert_cli.logger import LOGGER_CLI
from stream_alert_cli.outputs.helpers import encrypt_and_push_creds_to_s3, output_exists


def output_handler(options, config):
    """Configure a new output for this service

    Args:
        options (argparse.Namespace): Basically a namedtuple with the service setting
    """
    account_config = config['global']['account']
    region = account_config['region']
    prefix = account_config['prefix']
    kms_key_alias = account_config['kms_key_alias']
    # Verify that the word alias is not in the config.
    # It is interpolated when the API call is made.
    if 'alias/' in kms_key_alias:
        kms_key_alias = kms_key_alias.split('/')[1]

    # Retrieve the proper service class to handle dispatching the alerts of this services
    output = StreamAlertOutput.get_dispatcher(options.service)

    # If an output for this service has not been defined, the error is logged
    # prior to this
    if not output:
        return

    # get dictionary of OutputProperty items to be used for user prompting
    props = output.get_user_defined_properties()

    for name, prop in props.iteritems():
        # pylint: disable=protected-access
        props[name] = prop._replace(
            value=user_input(prop.description, prop.mask_input, prop.input_restrictions))

    output_config = config['outputs']
    service = output.__service__

    # If it exists already, ask for user input again for a unique configuration
    if output_exists(output_config, props, service):
        return output_handler(options, config)

    secrets_bucket = '{}.streamalert.secrets'.format(prefix)
    secrets_key = output.output_cred_name(props['descriptor'].value)

    # Encrypt the creds and push them to S3
    # then update the local output configuration with properties
    if encrypt_and_push_creds_to_s3(region, secrets_bucket, secrets_key, props, kms_key_alias):
        updated_config = output.format_output_config(output_config, props)
        output_config[service] = updated_config
        config.write()

        LOGGER_CLI.info('Successfully saved \'%s\' output configuration for service \'%s\'',
                        props['descriptor'].value, options.service)
    else:
        LOGGER_CLI.error('An error occurred while saving \'%s\' '
                         'output configuration for service \'%s\'', props['descriptor'].value,
                         options.service)
