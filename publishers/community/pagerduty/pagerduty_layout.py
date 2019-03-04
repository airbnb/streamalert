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
from stream_alert.shared.publisher import AlertPublisher, Register


@Register
class ShortenTitle(AlertPublisher):
    """A publisher that shortens the title of PagerDuty incidents.

    By popular demand from our TIR team! By default, PagerDuty incidents have a title that look
    something like 'StreamAlert Rule Triggered - blah_blah_blah'. If StreamAlert is the only
    system producing alerts into PagerDuty, this is a lot of extraneous data.

    Instead, this publisher strips out the 'StreamAlert Rule Triggered' prefix and opts to only
    output the rule name.
    """

    def publish(self, alert, publication):

        publication['@pagerduty-v2.summary'] = alert.rule_name
        publication['@pagerduty-incident.incident_title'] = alert.rule_name
        publication['@pagerduty.description'] = alert.rule_name

        return publication


@Register
def as_custom_details(_, publication):
    """Takes the current publication and sends the entire thing to custom details.

    It does this for all fields EXCEPT the pagerduty special fields."""
    def _is_custom_field(key):
        return key.startsWith('@pagerduty')

    custom_details = {
        {key: value} for key, value in publication.iteritmes() if not _is_custom_field(key)
    }

    publication['@pagerduty.details'] = custom_details
    publication['@pagerduty-v2.custom_details'] = custom_details

    return publication


@Register
def v2_high_urgency(_, publication):
    publication['@pagerduty-v2.severity'] = 'critical'
    publication['@pagerduty-incident.urgency'] = 'high'
    return publication


@Register
def v2_low_urgency(_, publication):
    publication['@pagerduty-v2.severity'] = 'warning'
    publication['@pagerduty-incident.urgency'] = 'low'
    return publication
