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
from unittest.mock import MagicMock, Mock, call, patch

# pylint: disable=protected-access,attribute-defined-outside-init,no-self-use,no-member
import pymsteams
from pymsteams import TeamsWebhookException

from streamalert.alert_processor.helpers import compose_alert
from streamalert.alert_processor.outputs.teams import TeamsOutput
from tests.unit.streamalert.alert_processor.helpers import (get_alert,
                                                            get_random_alert)


@patch(
    'streamalert.alert_processor.outputs.output_base.OutputDispatcher.MAX_RETRY_ATTEMPTS',
    1,
)
class TestTeamsOutput:
    """Test class for Teams"""

    DESCRIPTOR = 'unit_test_channel'
    SERVICE = 'teams'
    OUTPUT = ':'.join([SERVICE, DESCRIPTOR])
    CREDS = {
        'url': 'https://outlook.office.com/webhook/GUID@GUID/IncomingWebhook/WEBHOOK-ID/KEY'
    }

    @patch('streamalert.alert_processor.outputs.output_base.OutputCredentialsProvider')
    def setup(self, provider_constructor):
        """Setup before each method"""
        provider = MagicMock()
        provider_constructor.return_value = provider
        provider.load_credentials = Mock(
            side_effect=lambda x: self.CREDS if x == self.DESCRIPTOR else None
        )

        self._provider = provider
        self._dispatcher = TeamsOutput(None)

    @patch('pymsteams.cardsection')
    def test_generate_record_section(self, section_mock):
        """TeamsOutput - _generate_record_section - Teams"""
        section_mock.return_value = Mock(
            activityTitle=Mock(),
            addFact=Mock()
        )

        rule_name = 'test_rule_default'
        alert = get_random_alert(25, rule_name)

        section = self._dispatcher._generate_record_section(alert.record)

        # Tests
        section_mock.assert_called()
        section.activityTitle.assert_called()
        section.activityTitle.assert_called_with('StreamAlert Alert Record')
        section.addFact.assert_called()
        section.addFact.assert_has_calls(
            [
                call(key, value) for key, value in alert.record.items()
            ],
            any_order=True
        )

    @patch('pymsteams.cardsection')
    def test_generate_alert_section(self, section_mock):
        """TeamsOutput - _generate_alert_section - Teams"""
        section_mock.return_value = Mock(
            activityTitle=Mock(),
            addFact=Mock()
        )

        rule_name = 'test_rule_default'
        alert = get_random_alert(25, rule_name)

        section = self._dispatcher._generate_alert_section(alert)

        # Tests
        section_mock.assert_called()
        section.activityTitle.assert_called()
        section.activityTitle.assert_called_with('Alert Info')
        section.addFact.assert_called()
        section.addFact.assert_has_calls(
            [
                call('rule_name', alert.rule_name),
                call('alert_id', alert.alert_id)
            ],
            any_order=False
        )

    @patch('logging.Logger.error')
    def test_add_additional_sections_single_section(self, log_mock):
        """TeamsOutput - _add_additional_sections - single section"""
        teams_card = Mock(
            addSection=Mock()
        )
        section = Mock(spec=pymsteams.cardsection)

        teams_card = self._dispatcher._add_additional_sections(teams_card, section)

        # Tests
        teams_card.addSection.assert_called()
        teams_card.addSection.assert_called_with(section)
        log_mock.assert_not_called()

    @patch('logging.Logger.error')
    def test_add_additional_sections_multiple_sections(self, log_mock):
        """TeamsOutput - _add_additional_sections - multiple sections"""
        teams_card = Mock(
            addSection=Mock()
        )
        section_1 = Mock(spec=pymsteams.cardsection)
        section_2 = Mock(spec=pymsteams.cardsection)

        teams_card = self._dispatcher._add_additional_sections(teams_card, [section_1, section_2])

        # Tests
        teams_card.addSection.assert_called()
        teams_card.addSection.assert_has_calls(
            [
                call(section_1),
                call(section_2)
            ],
            any_order=False
        )
        log_mock.assert_not_called()

    @patch('logging.Logger.error')
    def test_add_additional_sections_logs_error(self, log_mock):
        """TeamsOutput - _add_additional_sections - logs error"""
        teams_card = Mock(
            addSection=Mock()
        )
        invalid_section = 'i am not a card section'

        teams_card = self._dispatcher._add_additional_sections(teams_card, [invalid_section])

        # Tests
        teams_card.addSection.assert_not_called()
        log_mock.assert_called()
        log_mock.assert_called_with(
            'additional_section: %s is not an instance of %s',
            invalid_section,
            pymsteams.cardsection,
        )

    def test_single_link_button(self):
        """TeamsOutput - _add_buttons - single button"""
        teams_card = Mock(
            addLinkButton=Mock()
        )

        button = ('button_text', 'button_url')
        teams_card = self._dispatcher._add_buttons(teams_card, [button])

        # Tests
        teams_card.addLinkButton.assert_called()
        teams_card.addLinkButton.assert_called_with(*button)

    def test_multiple_link_butons(self):
        """TeamsOutput - _add_buttons - multiple buttons"""
        teams_card = Mock(
            addLinkButton=Mock()
        )

        buttons = [
            ('button_one', 'url_one'),
            ('button_two', 'url_two')
        ]
        teams_card = self._dispatcher._add_buttons(teams_card, buttons)

        # Tests
        teams_card.addLinkButton.assert_called()
        teams_card.addLinkButton.assert_has_calls(
            [
                call(*buttons[0]),
                call(*buttons[1])
            ],
            any_order=False
        )

    @patch.object(TeamsOutput, '_generate_record_section')
    @patch.object(TeamsOutput, '_generate_alert_section')
    @patch('pymsteams.connectorcard', spec=pymsteams.connectorcard)
    def test_format_message_default(self, _, alert_section_mock, record_section_mock):
        """TeamsOutput - Format Default Message - Teams"""
        rule_name = 'test_rule_default'
        alert = get_random_alert(25, rule_name)
        output = MagicMock(spec=TeamsOutput)
        alert_publication = compose_alert(alert, output, 'asdf')

        alert_section_mock.return_value = 'Alert_Section'
        record_section_mock.return_value = 'Record_Section'

        loaded_message = self._dispatcher._format_message(
            alert, alert_publication, self.CREDS['url']
        )

        # Tests

        # Verify title
        loaded_message.title.assert_called()
        loaded_message.title.assert_called_with(f'StreamAlert Rule Triggered: {alert.rule_name}')

        # Verify text/description
        loaded_message.text.assert_called()
        loaded_message.text.assert_called_with(alert.rule_description)

        # Verify card color
        loaded_message.color.assert_called()
        loaded_message.color.assert_called_with('E81123')

        # Verify Sections
        alert_section_mock.assert_called()
        alert_section_mock.assert_called_with(alert)
        record_section_mock.assert_called()
        record_section_mock.assert_called_with(alert.record)
        loaded_message.addSection.assert_called()
        loaded_message.addSection.assert_has_calls(
            [
                call('Alert_Section'),
                call('Record_Section')
            ],
            any_order=False
        )

    @patch.object(TeamsOutput, '_generate_record_section')
    @patch.object(TeamsOutput, '_generate_alert_section')
    @patch('pymsteams.connectorcard', spec=pymsteams.connectorcard)
    def test_format_message_custom_title(self, _, alert_section_mock, record_section_mock):
        """TeamsOutput - Format Message - Custom Title"""
        rule_name = 'test_rule_default'
        alert = get_random_alert(25, rule_name)
        output = MagicMock(spec=TeamsOutput)
        alert_publication = compose_alert(alert, output, 'asdf')
        alert_publication['@teams.title'] = 'This is a test'

        alert_section_mock.return_value = 'Alert_Section'
        record_section_mock.return_value = 'Record_Section'

        loaded_message = self._dispatcher._format_message(
            alert, alert_publication, self.CREDS['url']
        )

        # Tests

        # Verify title
        loaded_message.title.assert_called()
        loaded_message.title.assert_called_with('This is a test')

        # Verify text/description
        loaded_message.text.assert_called()
        loaded_message.text.assert_called_with(alert.rule_description)

        # Verify card color
        loaded_message.color.assert_called()
        loaded_message.color.assert_called_with('E81123')

        # Verify Sections
        alert_section_mock.assert_called()
        alert_section_mock.assert_called_with(alert)
        record_section_mock.assert_called()
        record_section_mock.assert_called_with(alert.record)
        loaded_message.addSection.assert_called()
        loaded_message.addSection.assert_has_calls(
            [
                call('Alert_Section'),
                call('Record_Section')
            ],
            any_order=False
        )

    @patch.object(TeamsOutput, '_generate_record_section')
    @patch.object(TeamsOutput, '_generate_alert_section')
    @patch('pymsteams.connectorcard', spec=pymsteams.connectorcard)
    def test_format_message_custom_text(self, _, alert_section_mock, record_section_mock):
        """TeamsOutput - Format Message - Custom description / text"""
        rule_name = 'test_rule_default'
        alert = get_random_alert(25, rule_name)
        output = MagicMock(spec=TeamsOutput)
        alert_publication = compose_alert(alert, output, 'asdf')
        alert_publication['@teams.description'] = 'This is a test'

        alert_section_mock.return_value = 'Alert_Section'
        record_section_mock.return_value = 'Record_Section'

        loaded_message = self._dispatcher._format_message(
            alert, alert_publication, self.CREDS['url']
        )

        # Tests

        # Verify title
        loaded_message.title.assert_called()
        loaded_message.title.assert_called_with(f'StreamAlert Rule Triggered: {alert.rule_name}')

        # Verify text/description
        loaded_message.text.assert_called()
        loaded_message.text.assert_called_with('This is a test')

        # Verify card color
        loaded_message.color.assert_called()
        loaded_message.color.assert_called_with('E81123')

        # Verify Sections
        alert_section_mock.assert_called()
        alert_section_mock.assert_called_with(alert)
        record_section_mock.assert_called()
        record_section_mock.assert_called_with(alert.record)
        loaded_message.addSection.assert_called()
        loaded_message.addSection.assert_has_calls(
            [
                call('Alert_Section'),
                call('Record_Section')
            ],
            any_order=False
        )

    @patch.object(TeamsOutput, '_generate_record_section')
    @patch.object(TeamsOutput, '_generate_alert_section')
    @patch('pymsteams.connectorcard', spec=pymsteams.connectorcard)
    def test_format_message_custom_color(self, _, alert_section_mock, record_section_mock):
        """TeamsOutput - Format Message - Custom color"""
        rule_name = 'test_rule_default'
        alert = get_random_alert(25, rule_name)
        output = MagicMock(spec=TeamsOutput)
        alert_publication = compose_alert(alert, output, 'asdf')
        alert_publication['@teams.card_color'] = '46eb34'

        alert_section_mock.return_value = 'Alert_Section'
        record_section_mock.return_value = 'Record_Section'

        loaded_message = self._dispatcher._format_message(
            alert, alert_publication, self.CREDS['url']
        )

        # Tests

        # Verify title
        loaded_message.title.assert_called()
        loaded_message.title.assert_called_with(f'StreamAlert Rule Triggered: {alert.rule_name}')

        # Verify text/description
        loaded_message.text.assert_called()
        loaded_message.text.assert_called_with(alert.rule_description)

        # Verify card color
        loaded_message.color.assert_called()
        loaded_message.color.assert_called_with('46eb34')

        # Verify Sections
        alert_section_mock.assert_called()
        alert_section_mock.assert_called_with(alert)
        record_section_mock.assert_called()
        record_section_mock.assert_called_with(alert.record)
        loaded_message.addSection.assert_called()
        loaded_message.addSection.assert_has_calls(
            [
                call('Alert_Section'),
                call('Record_Section')
            ],
            any_order=False
        )

    @patch.object(TeamsOutput, '_generate_record_section')
    @patch.object(TeamsOutput, '_generate_alert_section')
    @patch('pymsteams.connectorcard', spec=pymsteams.connectorcard)
    def test_format_message_no_record(self, _, alert_section_mock, record_section_mock):
        """TeamsOutput - Format Message - No Record"""
        rule_name = 'test_rule_default'
        alert = get_random_alert(25, rule_name)
        output = MagicMock(spec=TeamsOutput)
        alert_publication = compose_alert(alert, output, 'asdf')
        alert_publication['@teams.with_record'] = False

        alert_section_mock.return_value = 'Alert_Section'
        record_section_mock.return_value = 'Record_Section'

        loaded_message = self._dispatcher._format_message(
            alert, alert_publication, self.CREDS['url']
        )

        # Tests

        # Verify title
        loaded_message.title.assert_called()
        loaded_message.title.assert_called_with(f'StreamAlert Rule Triggered: {alert.rule_name}')

        # Verify text/description
        loaded_message.text.assert_called()
        loaded_message.text.assert_called_with(alert.rule_description)

        # Verify card color
        loaded_message.color.assert_called()
        loaded_message.color.assert_called_with('E81123')

        # Verify Sections
        alert_section_mock.assert_called()
        alert_section_mock.assert_called_with(alert)
        record_section_mock.assert_not_called()
        loaded_message.addSection.assert_called()
        loaded_message.addSection.assert_has_calls(
            [
                call('Alert_Section')
            ],
            any_order=False
        )

    @patch.object(TeamsOutput, '_add_additional_sections')
    @patch.object(TeamsOutput, '_generate_record_section')
    @patch.object(TeamsOutput, '_generate_alert_section')
    @patch('pymsteams.connectorcard', spec=pymsteams.connectorcard)
    def test_format_message_additional_sections(
            self,
            _,
            alert_section_mock,
            record_section_mock,
            add_sections_mock
    ):
        """TeamsOutput - Format Message - Additional card sections"""
        rule_name = 'test_rule_default'
        alert = get_random_alert(25, rule_name)
        output = MagicMock(spec=TeamsOutput)
        alert_publication = compose_alert(alert, output, 'asdf')
        alert_publication['@teams.with_record'] = True

        # Setup test_card_section
        test_card_section = Mock()

        alert_section_mock.return_value = 'Alert_Section'
        record_section_mock.return_value = 'Record_Section'

        add_sections_mock.side_effect = (lambda teams_card, _: teams_card)

        # Pass card section in via Publisher
        alert_publication['@teams.additional_card_sections'] = [test_card_section]

        loaded_message = self._dispatcher._format_message(
            alert, alert_publication, self.CREDS['url']
        )

        # Tests

        # Verify title
        loaded_message.title.assert_called()
        loaded_message.title.assert_called_with(f'StreamAlert Rule Triggered: {alert.rule_name}')

        # Verify text/description
        loaded_message.text.assert_called()
        loaded_message.text.assert_called_with(alert.rule_description)

        # Verify card color
        loaded_message.color.assert_called()
        loaded_message.color.assert_called_with('E81123')

        # Verify Sections
        alert_section_mock.assert_called()
        alert_section_mock.assert_called_with(alert)
        record_section_mock.assert_called()
        record_section_mock.assert_called_with(alert.record)
        add_sections_mock.assert_called()
        assert add_sections_mock.call_count == 1
        loaded_message.addSection.assert_called()
        loaded_message.addSection.assert_has_calls(
            [
                call('Alert_Section'),
                call('Record_Section')
            ],
            any_order=False
        )

    @patch.object(TeamsOutput, '_add_buttons')
    @patch.object(TeamsOutput, '_generate_alert_section')
    @patch('pymsteams.connectorcard', spec=pymsteams.connectorcard)
    def test_format_message_buttons(
            self,
            _,
            alert_section_mock,
            add_buttons_mock
    ):
        """TeamsOutput - Format Message - Buttons"""
        rule_name = 'test_rule_default'
        alert = get_random_alert(25, rule_name)
        output = MagicMock(spec=TeamsOutput)
        alert_publication = compose_alert(alert, output, 'asdf')
        alert_publication['@teams.with_record'] = False

        alert_section_mock.return_value = 'Alert_Section'
        add_buttons_mock.side_effect = (lambda teams_card, _: teams_card)

        # Pass buttons in via publication
        buttons = [('button_text', 'button_url')]
        alert_publication['@teams.buttons'] = buttons

        loaded_message = self._dispatcher._format_message(
            alert, alert_publication, self.CREDS['url']
        )

        # Tests

        # Verify title
        loaded_message.title.assert_called()
        loaded_message.title.assert_called_with(f'StreamAlert Rule Triggered: {alert.rule_name}')

        # Verify text/description
        loaded_message.text.assert_called()
        loaded_message.text.assert_called_with(alert.rule_description)

        # Verify card color
        loaded_message.color.assert_called()
        loaded_message.color.assert_called_with('E81123')

        # Verify Sections
        alert_section_mock.assert_called()
        alert_section_mock.assert_called_with(alert)
        loaded_message.addSection.assert_called()
        loaded_message.addSection.assert_has_calls(
            [
                call('Alert_Section')
            ],
            any_order=False
        )

        # Verify buttons
        add_buttons_mock.assert_called()
        assert add_buttons_mock.call_count == 1

    @patch('logging.Logger.info')
    @patch.object(TeamsOutput, '_format_message')
    def test_dispatch_success(self, message_mock, log_mock):
        """TeamsOutput - Dispatch Success"""

        message_mock.return_value = Mock(
            send=Mock(return_value='Worked')
        )

        assert self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        # Tests
        log_mock.assert_called()
        log_mock.assert_called_with(
            'Successfully sent alert to %s:%s', self.SERVICE, self.DESCRIPTOR
        )

    @patch('logging.Logger.error')
    @patch.object(TeamsOutput, '_format_message')
    def test_dispatch_failure(self, message_mock, log_mock):
        """TeamsOutput - Dispatch Failure, Bad Request"""
        exception = TeamsWebhookException('BOOM!')

        message_mock.return_value = Mock(
            send=Mock(side_effect=exception)
        )
        assert not self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        # Tests
        log_mock.assert_called()
        log_mock.assert_has_calls(
            [
                call('Error Sending Alert to Teams: %s', exception),
                call('Failed to send alert to %s:%s', 'teams', 'unit_test_channel')
            ]
        )

    @patch('logging.Logger.error')
    @patch.object(TeamsOutput, '_load_creds')
    def test_dispatch_no_creds(self, creds_mock, log_mock):
        """TeamsOutput - Dispatch Failure, No Creds"""
        creds_mock.return_value = None
        descriptor = "bad_descriptor"

        # Tests
        assert not self._dispatcher.dispatch(
            get_alert(), ":".join([self.SERVICE, descriptor])
        )
        log_mock.assert_called()
        log_mock.assert_has_calls(
            [
                call('No credentials found for descriptor: %s', descriptor),
                call('Failed to send alert to %s:%s', self.SERVICE, descriptor)
            ],
            any_order=False
        )
