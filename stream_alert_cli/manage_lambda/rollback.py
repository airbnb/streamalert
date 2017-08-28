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
from stream_alert_cli import helpers
from stream_alert_cli.config import CLIConfig
from stream_alert_cli.terraform.generate import terraform_generate


CONFIG = CLIConfig()

def rollback(options):
    """Rollback the current production AWS Lambda version by 1

    Notes:
        Ignores if the production version is $LATEST
        Only rollsback if published version is greater than 1
    """
    clusters = CONFIG.clusters()

    if 'all' in options.processor:
        lambda_functions = {'rule_processor', 'alert_processor', 'athena_partition_refresh'}
    else:
        lambda_functions = {'{}_processor'.format(proc) for proc in options.processor
                            if proc != 'athena'}
        if 'athena' in options.processor:
            lambda_functions.add('athena_partition_refresh')

    for cluster in clusters:
        for lambda_function in lambda_functions:
            stream_alert_key = CONFIG['clusters'][cluster]['modules']['stream_alert']
            current_vers = stream_alert_key[lambda_function]['current_version']
            if current_vers != '$LATEST':
                current_vers = int(current_vers)
                if current_vers > 1:
                    new_vers = current_vers - 1
                    CONFIG['clusters'][cluster]['modules']['stream_alert'][lambda_function][
                        'current_version'] = new_vers
                    CONFIG.write()

    targets = ['module.stream_alert_{}'.format(x)
               for x in CONFIG.clusters()]

    if not terraform_generate(config=CONFIG):
        return

    helpers.tf_runner(targets=targets)
