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
import re


class RuleDescriptionParser(object):
    """Class that does fuzzy parsing information out of the rule description

    In general, rule descriptions follow a very FUZZY scheme where they are newline-delimited
    and have at most one field per line (although it's possible for a single field to span
    multiple lines). Each field is one or more words preceding a colon.

    Example:

        author:  Derek
        description: Blah lorem ipsum
                     bacon bleu cheese
        playbook: etc

    Another possible format is to have a string description preceding the set of (optional) fields:

    Example:

        This rule is triggered when the speed hits over 9000

        author: Derek
        playbook: etc

    Additionally, certain fields can have URL values. Long URLs are split across multiple lines
    but are conjoined in the final parsed product

    Example:

        author:   Derek
        reference: https://this.is.a.really.really/long/url
                        ?that=does+not+fit+on+one+line#but=gets%53eventually+smushed+together

    Lastly, by default all line breaks are stripped out. However, if there is a double-line-break
    in the middle of a text, this double-line-break will appear in the final text as two newline
    characters.

    Example:

        description:
            This is paragraph 1 and remains unbroken despite having
            a linebreak in the middle of it.

            However, this paragraph 2 is broken from paragraph 1 because
            it has a double break in between.
    """

    # Match alphanumeric, plus underscores, dashes, spaces, and & signs
    # Labels are a maximum of 20 characters long. They also never start with http or https
    _FIELD_REGEX = re.compile(
        r'^(?!http:|https:)(?P<field>[a-zA-Z\d\-_&\s]{0,20}):(?P<remainder>.*)$'
    )
    _URL_REGEX = re.compile(
        r'^(?:http(s)?://)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\$&\'\(\)\*\+,;=.]+$'
    )

    @classmethod
    def parse(cls, rule_description):
        """Parses a multiline rule description string

        Args:
            rule_description (str): The rule's description

        Return:
            dict: A dict mapping fields to lists of strings, each corresponding to a line belonging
                  to that field. All field names are lowercase.
        """
        rule_description = '' if not rule_description else rule_description
        tokens = [line.strip() for line in rule_description.strip().split('\n')]

        field_lines = {}

        current_field = 'description'
        for token in tokens:
            if current_field not in field_lines:
                field_lines[current_field] = []

            if not token:
                # preserve an empty line
                field_lines[current_field].append('')
                continue

            # Python regex does not support possessive qualifiers, which means it not easy
            # to write a regex that detects for \s++(?:http:) because operator will attempt to
            # give up characters to the negative lookahead. So, we strip the line first before
            # doing the negative lookahead.
            match = cls._FIELD_REGEX.match(token)

            if match is not None:
                current_field = match.group('field').strip().lower()
                value = match.group('remainder').strip()
            else:
                value = token

            if current_field not in field_lines:
                field_lines[current_field] = []
            field_lines[current_field].append(value)

        return field_lines

    @classmethod
    def present(cls, rule_description):
        def join_lines(lines):
            if not isinstance(lines, list) or len(lines) <= 0:
                return ''

            document = None
            buffered_newlines = ''
            for line in lines:
                if not line:
                    buffered_newlines += '\n'
                    continue

                if document is None:
                    buffered_newlines = ''
                    document = line
                else:
                    match = cls._URL_REGEX.match(document + line)
                    if match is not None:
                        document += line
                    else:
                        space = buffered_newlines if buffered_newlines else ' '
                        buffered_newlines = ''
                        document += space + line

            if document is None:
                document = ''

            return document

        fragments = cls.parse(rule_description)

        presentation = {
            'author': '',
            'description': '',
            'fields': {},
        }

        for key, value in fragments.iteritems():
            if key in ['author', 'maintainer']:
                presentation['author'] = join_lines(value)
            elif key in ['description']:
                presentation['description'] = join_lines(value)
            else:
                presentation['fields'][key] = join_lines(value)

        return presentation
