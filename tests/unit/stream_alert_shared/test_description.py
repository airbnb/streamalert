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
from nose.tools import assert_equal

from stream_alert.shared.description import RuleDescriptionParser


class TestRuleDescriptionParserParse(object):

    @staticmethod
    def test_simple():
        """RuleDescriptionParser - One Field"""

        # Should be able to parse the author out
        case = '''
author: Derek Wang
'''

        data = RuleDescriptionParser.parse(case)
        assert_equal(data, {'author': ['Derek Wang'], 'description': []})

    @staticmethod
    def test_strange_spacing():
        """RuleDescriptionParser - Spacing"""

        # This string contains random spaces before and after the author field.
        case = '''

    author: Derek Wang
    '''

        data = RuleDescriptionParser.parse(case)
        assert_equal(data, {'author': ['Derek Wang'], 'description': []})

    @staticmethod
    def test_no_fields():
        """RuleDescriptionParser - No Fields"""
        case = '''
This rule has no format and thus the entire
  string is considered to be lines of the
  description.
'''

        data = RuleDescriptionParser.parse(case)
        assert_equal(data, {
            'description': [
                'This rule has no format and thus the entire',
                'string is considered to be lines of the',
                'description.',
            ]
        })

    @staticmethod
    def test_misleading_fields():
        """RuleDescriptionParser - No Fields"""
        case = '''
    This rule has some colons in it in strange places. For example: right here
    But should not have fields because... reasons.
    '''

        data = RuleDescriptionParser.parse(case)
        assert_equal(data, {
            'description': [
                'This rule has some colons in it in strange places. For example: right here',
                'But should not have fields because... reasons.',
            ]
        })

    @staticmethod
    def test_multiple_fields():
        """RuleDescriptionParser - Multiple Fields"""
        case = '''
author: Derek Wang
owner:  Bobby Tables
'''

        data = RuleDescriptionParser.parse(case)
        assert_equal(data, {'author': ['Derek Wang'], 'description': [], 'owner': ['Bobby Tables']})

    @staticmethod
    def test_multiple_fields_multiple_lines():
        """RuleDescriptionParser - Multiple Fields and Multiple Lines"""
        case = '''
author: Derek Wang (CSIRT)
reference:  There is no cow level
            Greed is good
'''

        data = RuleDescriptionParser.parse(case)
        assert_equal(data, {
            'author': ['Derek Wang (CSIRT)'],
            'description': [],
            'reference': ['There is no cow level', 'Greed is good'],
        })

    @staticmethod
    def test_indentations():
        """RuleDescriptionParser - Indentations"""
        case = '''
    author: Derek Wang (CSIRT)
    description:  Lorem ipsum bacon jalapeno cheeseburger
                  I'm clearly hungry
                  Planet pied piper forest windmill
'''

        data = RuleDescriptionParser.parse(case)
        assert_equal(data, {
            'author': ['Derek Wang (CSIRT)'],
            'description': [
                'Lorem ipsum bacon jalapeno cheeseburger',
                "I'm clearly hungry",
                'Planet pied piper forest windmill',
            ]
        })

    @staticmethod
    def test_description_prefix():
        """RuleDescriptionParser - Multiple Fields and Multiple Lines"""
        case = '''
This rule triggers when the temperature of the boiler exceeds 9000

author: Derek Wang (CSIRT)
reference:  https://www.google.com
'''

        data = RuleDescriptionParser.parse(case)
        assert_equal(data, {
            'description': [
                'This rule triggers when the temperature of the boiler exceeds 9000',
                ''
            ],
            'author': ['Derek Wang (CSIRT)'],
            'reference': ['https://www.google.com'],
        })

    @staticmethod
    def test_special_characters():
        """RuleDescriptionParser - Special characters"""
        case = '''
    author: Derek Wang (CSIRT)

    ATT&CK Tactic:    Defense Evasion
    ATT&CK Technique: Obfuscated Files or Information
    ATT&CK URL:       https://attack.mitre.org/wiki/Technique/T1027
'''

        data = RuleDescriptionParser.parse(case)
        assert_equal(data, {
            'author': ['Derek Wang (CSIRT)', ''],
            'description': [],
            'att&ck tactic': ['Defense Evasion'],
            'att&ck technique': ['Obfuscated Files or Information'],
            'att&ck url': ['https://attack.mitre.org/wiki/Technique/T1027'],
        })


class TestRuleDescriptionParserPresent(object):

    @staticmethod
    def test_simple():
        """RuleDescriptionParser - present - One Field"""
        case = '''
author: Derek Wang
'''

        data = RuleDescriptionParser.present(case)
        assert_equal(data, {'author': 'Derek Wang', 'description': '', 'fields': {}})

    @staticmethod
    def test_multiple_fields_multiple_lines():
        """RuleDescriptionParser - present - Multi Line"""
        case = '''
author: Derek Wang
description:  This description
    has multiple lines
       with inconsistent indentation
'''

        data = RuleDescriptionParser.present(case)
        assert_equal(data, {
            'author': 'Derek Wang',
            'description': 'This description has multiple lines with inconsistent indentation',
            'fields': {}
        })

    @staticmethod
    def test_fields_with_multiline_urls():
        """RuleDescriptionParser - present - Multi Line Urls"""
        case = '''
author: Derek Wang
description:  Lorem ipsum bacon
              Cheeseburger
reference:    https://www.airbnb.com/
                    users/notifications
'''

        data = RuleDescriptionParser.present(case)
        assert_equal(data, {
            'author': 'Derek Wang',
            'description': 'Lorem ipsum bacon Cheeseburger',
            'fields': {
                'reference': 'https://www.airbnb.com/users/notifications'
            }
        })

    @staticmethod
    def test_fields_with_multiline_complex_urls():
        """RuleDescriptionParser - present - Multi Line Complex Urls"""
        case = '''
reference:    https://www.airbnb.com/
                    users/notifications
                      ?a=b&$=b20L#hash=value[0]
'''

        data = RuleDescriptionParser.present(case)
        assert_equal(data, {
            'author': '',
            'description': '',
            'fields': {
                'reference': 'https://www.airbnb.com/users/notifications?a=b&$=b20L#hash=value[0]'
            }
        })

    @staticmethod
    def test_fields_with_multiline_invalid_urls():
        """RuleDescriptionParser - present - Do not concat invalid URLs"""
        case = '''
reference:    https://www.airbnb.com/users/notifications
              Gets concatenated with this line with a space inbetween.
'''

        data = RuleDescriptionParser.present(case)
        assert_equal(data, {
            'author': '',
            'description': '',
            'fields': {
                'reference': (
                    'https://www.airbnb.com/users/notifications '
                    'Gets concatenated with this line with a space inbetween.'
                )
            }
        })

    @staticmethod
    def test_handle_multiple_urls():
        """RuleDescriptionParser - present - Do not use http: as field"""
        case = '''
reference:    https://www.airbnb.com/users/notifications
              https://www.airbnb.com/account/profile
    HTTP URL: https://www.airbnb.com/account/haha
'''

        data = RuleDescriptionParser.present(case)
        assert_equal(data, {
            'author': '',
            'description': '',
            'fields': {
                'reference': (
                    'https://www.airbnb.com/users/notifications'
                    'https://www.airbnb.com/account/profile'
                ),
                'http url': 'https://www.airbnb.com/account/haha'
            }
        })

    @staticmethod
    def test_two_linebreaks_equals_newline():
        """RuleDescriptionParser - present - Handle linebreaks"""
        case = '''
description:
    This is a long description where normal linebreaks like
    this one will simply cause the sentence to continue flowing
    as normal.

    However a double linebreak will cause a real newline character 
    to appear in the final product.


    And double linebreaks cause double newlines.
'''

        data = RuleDescriptionParser.present(case)
        assert_equal(data, {
            'author': '',
            'description': (
                'This is a long description where normal linebreaks like '
                'this one will simply cause the sentence to continue flowing '
                'as normal.\n'
                'However a double linebreak will cause a real newline character '
                'to appear in the final product.'
                '\n\n'
                'And double linebreaks cause double newlines.'
            ),
            'fields': {}
        })

    @staticmethod
    def test_url_plus_string():
        """RuleDescriptionParser - present - URL Plus String"""
        case = '''
    description:
        https://airbnb.com
    
        The above url is line broken from this comment.
    '''

        data = RuleDescriptionParser.present(case)
        assert_equal(data, {
            'author': '',
            'description': (
                'https://airbnb.com\n'
                'The above url is line broken from this comment.'
            ),
            'fields': {}
        })
