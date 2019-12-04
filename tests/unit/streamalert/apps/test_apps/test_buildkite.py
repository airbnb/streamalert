import os

from mock import Mock, patch
from moto import mock_ssm
from nose.tools import assert_equal, raises

from stream_alert.apps._apps.buildkite import BuildkiteApp, BuildkiteAppError

from tests.unit.stream_alert_apps.test_helpers import get_event, put_mock_params
from tests.unit.stream_alert_shared.test_config import get_mock_lambda_context


@mock_ssm
@patch.object(BuildkiteApp, 'type', Mock(return_value='type'))
class TestBuildkiteApp(object):
    """Test class for the BuildkiteApp"""
    # pylint: disable=protected-access,no-self-use

    @patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-east-1'})
    def setup(self):
        # pylint: disable=attribute-defined-outside-init
        self._test_app_name = 'buildkite_audit'
        put_mock_params(self._test_app_name)
        self._event = get_event(self._test_app_name)
        self._context = get_mock_lambda_context(self._test_app_name)
        self._app = BuildkiteApp(self._event, self._context)

    @patch('stream_alert.apps._apps.buildkite.BuildkiteApp._make_post_request')
    @patch('stream_alert.apps._apps.buildkite.BuildkiteApp._get_token')
    def test_gather_logs(self, mock_get_token, mock_make_post_request):
        mock_get_token.return_value = '26afff2f6996004847458481ee78240b573cd66a'
        mock_make_post_request.return_value = True, self.get_sample_response()
        logs = self._app._gather_logs()
        assert_equal(len(logs), 3)
        mock_get_token.assert_called_once()

    @raises(BuildkiteAppError)
    @patch('stream_alert.apps._apps.buildkite.BuildkiteApp._make_post_request')
    @patch('stream_alert.apps._apps.buildkite.BuildkiteApp._get_token')
    def test_gather_logs_error_response(self, _mock_get_token, mock_make_post_request):
        mock_make_post_request.return_value = True, self.get_sample_error_response()
        self._app._gather_logs()

    # pylint: disable=line-too-long
    def get_sample_response(self):
        return {
            'data': {
                'organization': {
                    'auditEvents': {
                        'count': 123,
                        'edges': [{
                            'node': {
                                'occurredAt': '2018-04-01T11:47:46Z',
                                'type': 'ORGANIZATION_INVITATION_CREATED',
                                'data': '''{
                                        "admin": true,
                                        "email": "sampleuser@probable.io",
                                        "team_roles": {
                                            "be2236ad-d9ba-4b86-8f30-34627b6d991e": "member"
                                        }
                                    }
                                    ''',
                                'actor': {
                                    'name': 'Sample User'
                                },
                                'subject': {
                                    'type': 'ORGANIZATION_INVITATION',
                                    'name': None
                                }
                            },
                            'cursor': 'ktkhMjAxOC0wNC0wMSAxMTo0Nzo0Ni44MjA4MzYwMDAgVVRD2SQ2M2RlMDlkMy1mOTU1LTRjNDMtODMxMy1jYmJiMTQ3YmQ0NDE='
                        }, {
                            'node': {
                                'occurredAt': '2018-03-31T19:40:51Z',
                                'type': 'ORGANIZATION_INVITATION_ACCEPTED',
                                'data': '''{
                                    "team_members": [{
                                        "uuid": "7df880dd-ef9e-4eb5-be21-01fe37221dcc"
                                    }],
                                    "organization_member": {
                                        "uuid": "648aa417-280a-471d-aeb0-be858589e962"
                                    }
                                }''',
                                'actor': {
                                    'name': 'Sample User'
                                },
                                'subject': {
                                    'type': 'ORGANIZATION_INVITATION',
                                    'name': None
                                }
                            },
                            'cursor': 'ktkhMjAxOC0wMy0zMSAxOTo0MDo1MS41MDQyODkwMDAgVVRD2SQ1ZjkyMWI5Yy1kODlhLTRkYTItOWY5ZC0xNDI3YWI5MDU1Mzk='
                        }, {
                            'node': {
                                'occurredAt': '2018-03-31T19:40:51Z',
                                'type': 'TEAM_MEMBER_CREATED',
                                'data': '''{
                                    "role": "member",
                                    "team": {
                                        "name": "Everyone",
                                        "slug": "everyone",
                                        "uuid": "be2236ad-d9ba-4b86-8f30-34627b6d991e"
                                    },
                                    "user": {
                                        "name": "Sample User",
                                        "uuid": "4843fce1-e84f-4056-be6e-7f1bf5110d76",
                                            "email": "sampleuser@probable.io"
                                    }
                                }''',
                                'actor': {
                                    'name': 'Sample User'
                                },
                                'subject': {
                                    'type': 'TEAM_MEMBER',
                                    'name': None
                                }
                            },
                            'cursor': 'ktkhMjAxOC0wMy0zMSAxOTo0MDo1MS40Nzg0MjgwMDAgVVRD2SQwYzIwMDQxYS0yN2VlLTQ5NGItODg4ZC1kNjJhMTU5ZThhNWM='
                        }],
                        'pageInfo': {
                            'startCursor': 'ktkhMjAxOC0wNC0wMSAxMTo0Nzo0Ni44MjA4MzYwMDAgVVRD2SQ2M2RlMDlkMy1mOTU1LTRjNDMtODMxMy1jYmJiMTQ3YmQ0NDE=',
                            'endCursor': 'ktkhMjAxOC0wMy0zMSAxOTo0MDo1MS40Nzg0MjgwMDAgVVRD2SQwYzIwMDQxYS0yN2VlLTQ5NGItODg4ZC1kNjJhMTU5ZThhNWM=',
                            'hasPreviousPage': True,
                            'hasNextPage': False
                        }
                    }
                }
            }
        }

    def get_sample_error_response(self):
        return {'errors': [{'message': 'Unexpected end of document'}], 'type': 'graphql_parse_error'}
