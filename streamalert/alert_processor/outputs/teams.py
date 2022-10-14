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
from collections import OrderedDict

import pymsteams
from pymsteams import TeamsWebhookException

from streamalert.alert_processor.helpers import compose_alert
from streamalert.alert_processor.outputs.output_base import (OutputDispatcher,
                                                             OutputProperty,
                                                             StreamAlertOutput)
from streamalert.shared.logger import get_logger

LOGGER = get_logger(__name__)


@StreamAlertOutput
class TeamsOutput(OutputDispatcher):
    """TeamsOutput handles all alert dispatching for Microsoft Teams"""

    __service__ = "teams"

    @classmethod
    def get_user_defined_properties(cls):
        """Get properties that must be assigned by the user when configuring a new Microsoft Teams
        output.  This should be sensitive or unique information for this use-case that needs
        to come from the user.

        Every output should return a dict that contains a 'descriptor' with a description of the
        integration being configured.

        Microsoft Teams also requires a user provided 'webhook' url that is composed of the Team's
        api url and the unique integration key for this output. This value should be should be
        masked during input and is a credential requirement.

        Returns:
            OrderedDict: Contains various OutputProperty items
        """
        return OrderedDict([
            (
                "descriptor",
                OutputProperty(
                    description="a short and unique descriptor for this service configuration "
                    "(ie: name of Team the webhook relates too)"),
            ),
            (
                "url",
                OutputProperty(
                    description="the full teams webhook url, including the secret",
                    mask_input=True,
                    cred_requirement=True,
                ),
            ),
        ])

    @classmethod
    def _format_message(cls, alert, publication, webhook_url):
        """Format the message to be sent to Teams

        Args:
            alert (Alert): The alert
            publication (dict): Alert relevant to the triggered rule
            webhook_url (str): The webhook_url to send the card too

        Returns:
            pymsteams.connectorcard: The message to be sent to Teams
                The card will look like (by Default):
                    StreamAlert Rule Triggered: rule_name
                    Rule Description:
                    This will be the docstring from the rule, sent as the rule_description

                    Record:
                      key   value
                      key   value
                      ...
        """
        # Presentation defaults
        default_title = f"StreamAlert Rule Triggered: {alert.rule_name}"
        default_description = alert.rule_description
        default_color = "E81123"  # Red in Hexstring format

        # Special field that Publishers can use to customize the message
        title = publication.get("@teams.title", default_title)
        description = publication.get("@teams.description", default_description)
        card_color = publication.get("@teams.card_color", default_color)
        with_record = publication.get("@teams.with_record", True)

        # Instantiate the card with the url
        teams_card = pymsteams.connectorcard(webhook_url)

        # Set the cards title, text and color
        teams_card.title(title)
        teams_card.text(description)
        teams_card.color(card_color)

        # Add the Alert Section
        teams_card.addSection(cls._generate_alert_section(alert))

        if with_record:
            # Add the record Section
            teams_card.addSection(cls._generate_record_section(alert.record))

        if "@teams.additional_card_sections" in publication:
            teams_card = cls._add_additional_sections(
                teams_card, publication["@teams.additional_card_sections"])

        if "@teams.buttons" in publication:
            teams_card = cls._add_buttons(teams_card, publication["@teams.buttons"])

        return teams_card

    @classmethod
    def _generate_record_section(cls, record):
        """Generate the record section

        This adds the entire record to a section as key/value pairs

        Args:
            record (dict): The record that triggered the alert

        Returns:
            record_section (pymsteams.cardsection): record section for the outgoing card
        """
        # Instantiate the card section
        record_section = pymsteams.cardsection()

        # Set the title
        record_section.activityTitle("StreamAlert Alert Record")

        # Add the record as key/value pairs
        for key, value in record.items():
            record_section.addFact(key, str(value))

        return record_section

    @classmethod
    def _generate_alert_section(cls, alert):
        """Generate the alert section

        Args:
            alert (Alert): The alert

        Returns:
            alert_section (pymsteams.cardsection): alert section for the outgoing card
        """

        # Instantiate the card
        alert_section = pymsteams.cardsection()

        # Set the title
        alert_section.activityTitle("Alert Info")

        # Add basic information to the alert section
        alert_section.addFact("rule_name", alert.rule_name)
        alert_section.addFact("alert_id", alert.alert_id)

        return alert_section

    @staticmethod
    def _add_additional_sections(teams_card, additional_sections):
        """Add additional card sections to the teams card

        Args:
            teams_card (pymsteams.connectorcard): Teams connector card
            additional_sections (list[pymsteams.cardsection]):
                Additional sections to be added to the card. Each section should be of
                type: pymsteams.cardsection and have their relevant fields filled out.
                Please review the pymsteams documentation for additional information.

        Returns:
            teams_card (pymsteams.connectorcard): teams_card with additional sections added
        """
        if not isinstance(additional_sections, list):
            LOGGER.debug("additional_sections is not a list, converting")

            additional_sections = [additional_sections]

        for additional_section in additional_sections:
            if not isinstance(additional_section, pymsteams.cardsection):
                LOGGER.error(
                    "additional_section: %s is not an instance of %s",
                    additional_section,
                    pymsteams.cardsection,
                )
                continue

            teams_card.addSection(additional_section)

        return teams_card

    @staticmethod
    def _add_buttons(teams_card, buttons):
        """Add buttons to the teams card

        Args:
            teams_card (pymsteams.connectorcard): Teams connector card
            buttons (list[(text, url)]):
                Buttons to place on the card, should be a list of tuples containing
                the text and the url

        Returns:
            teams_card (pymsteams.connectorcard): teams_card with buttons added
        """
        for button_text, button_url in buttons:
            teams_card.addLinkButton(button_text, button_url)

        return teams_card

    def _dispatch(self, alert, descriptor):
        """Sends the Teams Card to Teams

        Publishing:
            By default the teams output sends a teams card comprising some default intro text
            and a section containing:
            * title with rule name
            * alert description
            * alert record (as a section of key/value pairs)

            To override this behavior use the following fields:

            - @teams.title (str):
                Replaces the title of the teams connector card.

            - @teams.description (str):
                Replaces the text of the team connector card

            - @teams.card_color (str):
                Replaces the default color of the connector card (red)
                Note: colors are represented by hex string

            - @teams.with_record (bool):
                Set to False, to remove the alert record section. Useful if you want to have a
                more targeted approach for the alert

            - @teams.additional_card_sections (list[pymsteams.cardsection]):
                Pass in additional sections you want to send on the message.

                @see cls._add_additional_sections() for more info

            - @teams.buttons (list[(text, url)])
                Pass a list of tuples containing the button text and url

                These will be placed at the bottom of a teams card

        Args:
            alert (Alert): Alert instance which triggered a rule
            descriptor (str): Output descriptor

        Returns:
            bool: True if alert was sent successfully, False otherwise
        """
        creds = self._load_creds(descriptor)
        if not creds:
            LOGGER.error("No credentials found for descriptor: %s", descriptor)
            return False

        # Create the publication
        publication = compose_alert(alert, self, descriptor)

        # Format the message
        teams_card = self._format_message(alert, publication, creds["url"])

        try:
            teams_card.send()
        except TeamsWebhookException as err:
            LOGGER.error("Error Sending Alert to Teams: %s", err)
            return False

        return True
