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

REQUIRED_OUTPUTS = {
    'aws-firehose': {
        'alerts': '{prefix}_streamalert_alert_delivery',
    }
}

def get_required_outputs():
    """Iterates through the required outputs and collapses to the right format

    Returns:
        set: Set of required output services and names in the form service:name
    """
    outputs = set()
    for service, value in REQUIRED_OUTPUTS.iteritems():
        if not isinstance(value, dict):
            continue
        outputs.update({'{}:{}'.format(service, output) for output in value.keys()})
    return outputs


def merge_required_outputs(user_config, prefix):
    """Iterates through the required outputs and merges them with the user outputs

    Args:
        user_config (dict): Loaded user outputs dictionary from conf/outputs.json
        prefix (str): Prefix for this StreamAlert deployment to be injected into
            resource names

    Returns:
        dict: Entire formatted outputs dictionary, including required items and
            user defined outputs
    """
    for service, value in REQUIRED_OUTPUTS.iteritems():
        if not isinstance(value, dict):
            continue

        # Format the resource with the prefix value
        for output, resource in value.iteritems():
            value[output] = resource.format(prefix=prefix)

        # Add the outputs for this service if none are defined
        if service not in user_config:
            user_config[service] = value
            continue

        # Merge the outputs with existing ones for this service
        user_config[service].update(value)

    return user_config
