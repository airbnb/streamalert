"""
Copyright 2017-present, Improbable Worlds Ltd.

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

import json
import re
from datetime import datetime

from . import AppIntegration, StreamAlertApp, get_logger

LOGGER = get_logger(__name__)


class BuildkiteAppError(Exception):
    """Buildkite App Error class"""


@StreamAlertApp
class BuildkiteApp(AppIntegration):
    """Buildkite StreamAlert app"""

    # TODO: move these into configurable flags that can be set externally
    # using the config system.
    _BUILDKITE_GRAPHQL_ENDPOINT = 'https://graphql.buildkite.com/v1'
    _PAGE_SIZE = 500
    _DATETIME_TEMPLATE = '%Y-%m-%dT%H:%M:%SZ'

    _audit_events_query = """
        query {{
          organization(slug: "{bk_organisation}") {{
            auditEvents(last:{query_size} before:{before_cursor}) {{
              count
              edges {{
                node {{
                  type
                  occurredAt
                  actor {{
                    name
                  }}
                  subject {{
                    name
                    type
                  }}
                  data
                }}
                cursor
              }}
              pageInfo {{
                startCursor
                endCursor
                hasPreviousPage
                hasNextPage
              }}
            }}
          }}
        }}
    """

    _all_queries = {
        'audit_events': {
            'query': _audit_events_query.format,
            'cursor_location_in_response':
                lambda r: r['data']['organization']['auditEvents']['pageInfo']['startCursor'],
            'edges_location_in_response':
                lambda r: r['data']['organization']['auditEvents']['edges']
        }
    }

    def __init__(self, event, context):
        super(BuildkiteApp, self).__init__(event, context)
        self._ssm_client = None
        self._result = []
        self._before_cursor = None

    @classmethod
    def service(cls):
        return 'buildkite'

    @classmethod
    def _type(cls):
        return 'audit'

    @classmethod
    def _required_auth_info(cls):
        return {
            'token': {
                'description': 'bearer token to access BuildKite GraphQL',
                'format': re.compile(r'^[a-f0-9]{40}$')
            },
            'buildkite_organisation': {
                'description': 'bearer token to access BuildKite GraphQL',
                'format': re.compile(r'^[a-f0-9]{40}$')
            }
        }

    def _sleep_seconds(self):
        return 0

    def _gather_logs(self):
        cursor_last_id = self._context.get('last_cursor_id', [])
        LOGGER.debug('[%s] cursor_last_id set to [%s]', self, cursor_last_id)
        cursors_changed = False
        retrieved_logs = []
        for name, instance in self._all_queries.items():
            if not cursor_last_id:
                self._before_cursor = "null"
            else:
                self._before_cursor = '"{}"'.format(cursor_last_id)
            LOGGER.debug('[%s] self._before_cursor to value [%s]', self, self._before_cursor)
            current_query = {
                'query': instance['query'](
                    query_size=self._PAGE_SIZE, before_cursor=self._before_cursor,
                    bk_organisation=self._get_bk_organisation())}

            success, response = self._make_post_request(self._BUILDKITE_GRAPHQL_ENDPOINT,
                                                        data=current_query,
                                                        headers=self._get_headers(),
                                                        is_json=True)
            LOGGER.debug('[%s] Current Query is [%s]', self, current_query)
            if not success:
                # Do not need to log anything here because _make_post_request does that already
                return []
            try:
                nodes = [edge['node']
                         for edge in instance['edges_location_in_response'](response)]
            except KeyError as err:
                m_template = (
                    '[%s] Could not obtain edges from response: %s.'
                    ' Response was "%s". Query was "%s"')
                LOGGER.exception(m_template,
                                 self, err, response, current_query)
                raise BuildkiteAppError(m_template.format(self, err, response, current_query))
            if not nodes:
                LOGGER.info('[%s] Did not get any new logs for "%s" query', self, name)
                continue
            now = datetime.now().strftime(self._DATETIME_TEMPLATE)

            for node in nodes:
                node['data'] = json.loads(node['data'])
                node['receivedAt'] = now

            cursors = response
            cursors_changed = True
            try:
                cursors[name] = instance['cursor_location_in_response'](response)
                LOGGER.debug('[%s] Succesfully found cursor value is "%s"', self, cursors[name])
            except KeyError as err:
                m_template = (
                    '[%s] Could not obtain cursor from response: %s.'
                    ' Response was "%s". #Query was "%s"')
                LOGGER.exception(m_template,
                                 self, err, response, current_query)
                raise BuildkiteAppError(m_template.format(self, err, response, current_query))
            self._more_to_poll = True
            self._last_timestamp = now
            LOGGER.debug('[%s] Received %d logs for "%s" query', self, len(nodes), name)
            retrieved_logs.extend(nodes)

        if cursors_changed:
            self._context['last_cursor_id'] = json.dumps(cursors['audit_events']).replace('\"', '')
            LOGGER.info('[%s] Written cursor as %s',
                        self, json.dumps(cursors['audit_events']).replace('\"', ''))
        return retrieved_logs

    def _get_headers(self):
        return {
            'Authorization': 'Bearer ' + self._get_token()
        }

    def _get_token(self):
        return self._config.auth['token']

    def _get_bk_organisation(self):
        return self._config.auth['buildkite_organisation']
