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
from publishers.community.generic import StringifyArrays
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

    It does this for all fields EXCEPT the pagerduty special fields.
    """
    def _is_custom_field(key):
        return key.startswith('@pagerduty')

    custom_details = {
        key: value for key, value in publication.iteritems() if not _is_custom_field(key)
    }

    publication['@pagerduty.details'] = custom_details
    publication['@pagerduty-v2.custom_details'] = custom_details

    return publication


@Register
def v2_high_urgency(_, publication):
    """Designates this alert as critical or high urgency

    This only works for pagerduty-v2 and pagerduty-incident Outputs. The original pagerduty
    integration uses the Events v1 API which does not support urgency.
    """
    publication['@pagerduty-v2.severity'] = 'critical'
    publication['@pagerduty-incident.urgency'] = 'high'
    return publication


@Register
def v2_low_urgency(_, publication):
    """Designates this alert as a warning or low urgency

    This only works for pagerduty-v2 and pagerduty-incident Outputs. The original pagerduty
    integration uses the Events v1 API which does not support urgency.
    """
    publication['@pagerduty-v2.severity'] = 'warning'
    publication['@pagerduty-incident.urgency'] = 'low'
    return publication


@Register
class PrettyPrintArrays(StringifyArrays):
    """Deeply navigates a dict publication and coverts all scalar arrays to strings

    Scalar arrays render poorly on PagerDuty's default UI. Newlines are ignored, and the scalar
    values are wrapped with quotations:

        [
          "element_here\n with newlines\noh no",
          "hello world\nhello world"
        ]

    This method searches the publication dict for scalar arrays and transforms them into strings
    by joining their values with the provided delimiter. This converts the above array into:

        element here
        with newlines
        oh no

        ----------

        hello world
        hello world
    """
    DELIMITER = '\n\n----------\n\n'


@Register
class AttachImage(StringifyArrays):
    """Attaches the given image to the PagerDuty request

    Works for both the v1 and v2 event api integrations.

    It is recommended to subclass this class with your own implementation of _image_url(),
    _click_url() and _alt_text() so that you can customize your own image.
    """
    IMAGE_URL = 'https://streamalert.io/en/stable/_images/sa-banner.png'
    IMAGE_CLICK_URL = 'https://streamalert.io/en/stable/'
    IMAGE_ALT_TEXT = 'StreamAlert Docs'

    def publish(self, alert, publication):
        publication['@pagerduty-v2.images'] = publication.get('@pagerduty-v2.images', [])
        publication['@pagerduty-v2.images'].append({
            'src': self._image_url(),
            'href': self._click_url(),
            'alt': self._alt_text(),
        })

        publication['@pagerduty.contexts'] = publication.get('@pagerduty.contexts', [])
        publication['@pagerduty.contexts'].append({
            'type': 'image',
            'src': self._image_url(),
        })

        return publication

    @classmethod
    def _image_url(cls):
        return cls.IMAGE_URL

    @classmethod
    def _click_url(cls):
        return cls.IMAGE_CLICK_URL

    @classmethod
    def _alt_text(cls):
        return cls.IMAGE_ALT_TEXT
