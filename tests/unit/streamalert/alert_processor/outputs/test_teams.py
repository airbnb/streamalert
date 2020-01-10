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
# pylint: disable=protected-access,attribute-defined-outside-init,no-self-use
import pymsteams
from mock import MagicMock, Mock, patch
from nose.tools import assert_equal, assert_false, assert_set_equal, assert_true

from streamalert.alert_processor.helpers import compose_alert
from streamalert.alert_processor.outputs.teams import TeamsOutput
from tests.unit.streamalert.alert_processor.helpers import get_alert, get_random_alert


@patch(
    "streamalert.alert_processor.outputs.output_base.OutputDispatcher.MAX_RETRY_ATTEMPTS",
    1,
)
class TestTeamsOutput:
    """Test class for Teams"""

    DESCRIPTOR = "unit_test_channel"
    SERVICE = "teams"
    OUTPUT = ":".join([SERVICE, DESCRIPTOR])
    CREDS = {
        "url": "https://outlook.office.com/webhook/GUID@GUID/IncomingWebhook/WEBHOOK-ID/KEY"
    }

    @patch("streamalert.alert_processor.outputs.output_base.OutputCredentialsProvider")
    def setup(self, provider_constructor):
        """Setup before each method"""
        provider = MagicMock()
        provider_constructor.return_value = provider
        provider.load_credentials = Mock(
            side_effect=lambda x: self.CREDS if x == self.DESCRIPTOR else None
        )

        self._provider = provider
        self._dispatcher = TeamsOutput(None)

    def test_format_message_default(self):
        """TeamsOutput - Format Default Message - Teams"""
        rule_name = "test_rule_default"
        alert = get_random_alert(25, rule_name)
        output = MagicMock(spec=TeamsOutput)
        alert_publication = compose_alert(alert, output, "asdf")

        loaded_message = TeamsOutput._format_message(
            alert, alert_publication, self.CREDS["url"]
        )
        payload = loaded_message.payload

        # tests
        assert_set_equal(
            set(payload.keys()), {"title", "text", "themeColor", "sections"}
        )
        assert_equal(payload["title"], "StreamAlert Rule Triggered: test_rule_default")
        assert_equal(len(payload["sections"]), 1)

    def test_format_message_custom_title(self):
        """TeamsOutput - Format Message - Custom Title"""
        rule_name = "test_rule_default"
        alert = get_random_alert(25, rule_name)
        output = MagicMock(spec=TeamsOutput)
        alert_publication = compose_alert(alert, output, "asdf")
        alert_publication["@teams.title"] = "This is a test"

        loaded_message = TeamsOutput._format_message(
            alert, alert_publication, self.CREDS["url"]
        )
        payload = loaded_message.payload

        # tests
        assert_set_equal(
            set(payload.keys()), {"title", "text", "themeColor", "sections"}
        )
        assert_equal(payload["title"], "This is a test")
        assert_equal(len(payload["sections"]), 1)

    def test_format_message_custom_description(self):
        """TeamsOutput - Format Message - Custom description"""
        rule_name = "test_rule_default"
        alert = get_random_alert(25, rule_name)
        output = MagicMock(spec=TeamsOutput)
        alert_publication = compose_alert(alert, output, "asdf")
        alert_publication["@teams.description"] = "This is a test"

        loaded_message = TeamsOutput._format_message(
            alert, alert_publication, self.CREDS["url"]
        )
        payload = loaded_message.payload

        # tests
        assert_set_equal(
            set(payload.keys()), {"title", "text", "themeColor", "sections"}
        )
        assert_equal(payload["text"], "This is a test")
        assert_equal(len(payload["sections"]), 1)

    def test_format_message_custom_color(self):
        """TeamsOutput - Format Message - Custom color"""
        rule_name = "test_rule_default"
        alert = get_random_alert(25, rule_name)
        output = MagicMock(spec=TeamsOutput)
        alert_publication = compose_alert(alert, output, "asdf")
        alert_publication["@teams.card_color"] = "46eb34"

        loaded_message = TeamsOutput._format_message(
            alert, alert_publication, self.CREDS["url"]
        )
        payload = loaded_message.payload

        # tests
        assert_set_equal(
            set(payload.keys()), {"title", "text", "themeColor", "sections"}
        )
        assert_equal(payload["themeColor"], "46eb34")
        assert_equal(len(payload["sections"]), 1)

    def test_format_message_no_record(self):
        """TeamsOutput - Format Message - No Record"""
        rule_name = "test_rule_default"
        alert = get_random_alert(25, rule_name)
        output = MagicMock(spec=TeamsOutput)
        alert_publication = compose_alert(alert, output, "asdf")
        alert_publication["@teams.with_record"] = False

        loaded_message = TeamsOutput._format_message(
            alert, alert_publication, self.CREDS["url"]
        )
        payload = loaded_message.payload

        # tests
        assert_set_equal(set(payload.keys()), {"title", "text", "themeColor"})
        assert_false(payload.get("sections"))

    def test_format_message_additional_sections_with_record(self):
        """TeamsOutput - Format Message - Additional card sections with record"""
        rule_name = "test_rule_default"
        alert = get_random_alert(25, rule_name)
        output = MagicMock(spec=TeamsOutput)
        alert_publication = compose_alert(alert, output, "asdf")
        alert_publication["@teams.with_record"] = True

        # Setup test_card_section
        test_card_section = pymsteams.cardsection()
        test_card_section.title("test_section")
        test_card_section.activityText("this is test section")
        test_card_section.addFact("test", True)

        # Pass card section in via Publisher
        alert_publication["@teams.additional_card_sections"] = [test_card_section]

        loaded_message = TeamsOutput._format_message(
            alert, alert_publication, self.CREDS["url"]
        )
        card_payload = loaded_message.payload

        # tests
        assert_set_equal(
            set(card_payload.keys()), {"title", "text", "themeColor", "sections"}
        )
        assert_equal(len(card_payload["sections"]), 2)

        # Verify first section is the record
        assert_equal(
            card_payload["sections"][0]["activityTitle"], "StreamAlert Alert Record"
        )

        # Verify the second section is the passed in test_card_section
        assert_equal(card_payload["sections"][1], test_card_section.payload)

    @patch("logging.Logger.debug")
    def test_format_message_single_section_no_record(self, log_mock):
        """TeamsOutput - Format Message - single card section with no record"""
        rule_name = "test_rule_default"
        alert = get_random_alert(25, rule_name)
        output = MagicMock(spec=TeamsOutput)
        alert_publication = compose_alert(alert, output, "asdf")
        alert_publication["@teams.with_record"] = False

        # Setup test_card_section
        test_card_section = pymsteams.cardsection()
        test_card_section.title("test_section")
        test_card_section.activityText("this is test section")
        test_card_section.addFact("test", True)

        # Pass card section in via Publisher
        alert_publication["@teams.additional_card_sections"] = test_card_section

        loaded_message = TeamsOutput._format_message(
            alert, alert_publication, self.CREDS["url"]
        )
        card_payload = loaded_message.payload

        # tests
        assert_set_equal(
            set(card_payload.keys()), {"title", "text", "themeColor", "sections"}
        )
        assert_equal(len(card_payload["sections"]), 1)

        # Verify the section is the passed in test_card_section
        assert_equal(card_payload["sections"][0], test_card_section.payload)
        log_mock.assert_called_with("additional_sections is not a list, converting")

    def test_format_message_multiple_sections_no_record(self):
        """TeamsOutput - Format Message - Multiple card sections with no record"""
        rule_name = "test_rule_default"
        alert = get_random_alert(25, rule_name)
        output = MagicMock(spec=TeamsOutput)
        alert_publication = compose_alert(alert, output, "asdf")
        alert_publication["@teams.with_record"] = False

        # Setup test_card_section
        test_card_section = pymsteams.cardsection()
        test_card_section.title("test_section")
        test_card_section.activityText("this is test section")
        test_card_section.addFact("test", True)

        # Pass card section in via Publisher
        alert_publication["@teams.additional_card_sections"] = [
            test_card_section,
            test_card_section,
        ]

        loaded_message = TeamsOutput._format_message(
            alert, alert_publication, self.CREDS["url"]
        )
        card_payload = loaded_message.payload

        # tests
        assert_set_equal(
            set(card_payload.keys()), {"title", "text", "themeColor", "sections"}
        )
        assert_equal(len(card_payload["sections"]), 2)

        # Verify the first and second section is the passed in test_card_section
        assert_equal(card_payload["sections"][0], test_card_section.payload)
        assert_equal(card_payload["sections"][1], test_card_section.payload)

    @patch("logging.Logger.error")
    def test_format_message_invalid_section(self, log_mock):
        """TeamsOutput - Format Message - invalid section passed"""
        rule_name = "test_rule_default"
        alert = get_random_alert(25, rule_name)
        output = MagicMock(spec=TeamsOutput)
        alert_publication = compose_alert(alert, output, "asdf")
        alert_publication["@teams.with_record"] = False

        # Setup test_card_section
        test_card_section = "invalid section"

        # Pass card section in via Publisher
        alert_publication["@teams.additional_card_sections"] = test_card_section

        loaded_message = TeamsOutput._format_message(
            alert, alert_publication, self.CREDS["url"]
        )
        card_payload = loaded_message.payload

        # tests
        assert_set_equal(set(card_payload.keys()), {"title", "text", "themeColor"})
        log_mock.assert_called_with(
            "additional_section: %s is not an instance of %s",
            test_card_section,
            pymsteams.cardsection,
        )

    @patch("logging.Logger.info")
    @patch("requests.post")
    def test_dispatch_success(self, url_mock, log_mock):
        """TeamsOutput - Dispatch Success"""
        url_mock.return_value.status_code = 200
        url_mock.return_value.json.return_value = dict()

        assert_true(self._dispatcher.dispatch(get_alert(), self.OUTPUT))

        log_mock.assert_called_with(
            "Successfully sent alert to %s:%s", self.SERVICE, self.DESCRIPTOR
        )

    @patch("logging.Logger.error")
    @patch("requests.post")
    def test_dispatch_failure(self, url_mock, log_mock):
        """TeamsOutput - Dispatch Failure, Bad Request"""
        json_error = {"message": "error message", "errors": ["error1"]}
        url_mock.return_value.json.return_value = json_error
        url_mock.return_value.status_code = 400

        assert_false(self._dispatcher.dispatch(get_alert(), self.OUTPUT))

        log_mock.assert_called_with(
            "Failed to send alert to %s:%s", self.SERVICE, self.DESCRIPTOR
        )

    @patch("logging.Logger.error")
    def test_dispatch_bad_descriptor(self, log_mock):
        """TeamsOutput - Dispatch Failure, Bad Descriptor"""
        assert_false(
            self._dispatcher.dispatch(
                get_alert(), ":".join([self.SERVICE, "bad_descriptor"])
            )
        )

        log_mock.assert_called_with(
            "Failed to send alert to %s:%s", self.SERVICE, "bad_descriptor"
        )
