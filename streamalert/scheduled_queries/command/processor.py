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
from logging import Logger

from streamalert.scheduled_queries.query_packs.manager import QueryPacksManager
from streamalert.scheduled_queries.state.state_manager import StateManager
from streamalert.scheduled_queries.streamalert.kinesis import KinesisClient


class CommandProcessor:
    def __init__(self, logger=None, kinesis=None, state_manager=None, manager_factory=None):
        self._logger = logger  # type: Logger
        self._kinesis = kinesis  # type: KinesisClient
        self._state_manager = state_manager  # type: StateManager
        self._manager = manager_factory.new_manager()  # type: QueryPacksManager

    def nonblocking_single_pass(self):
        """Make a single, nonblocking pass through all Queries that are configured to run.

        It is up to the caller to call this method over and over.

        Return:
            bool: True when all work is finished. False otherwise.
        """
        self._logger.info(
            f'Discovered {self._manager.num_registered_queries} query packs to execute')

        self._manager.initialize_query_packs()
        self._manager.start_queries()

        finished_queries = self._manager.finished_query_packs

        for query_pack in finished_queries:
            self._handle_finished_query(query_pack)

        if len(finished_queries) == self._manager.num_registered_queries:
            self._logger.info('All queries completed.')
            return True

        return False

    def _handle_finished_query(self, query_pack):
        """Figures out what to do with a QueryPack that has finished running.

        This method is Idempotent.

        Arguments:
            query_pack (QueryPack)
        """
        query_execution = query_pack.query_execution
        query_execution_id = query_pack.query_execution_id

        # If query pack is sent
        if self._query_pack_already_sent(query_pack):
            self._logger.debug('  Already sent to Kinesis.')
            return

        if not query_execution.is_succeeded():
            # uh o
            self._logger.error('ENCOUNTERED ERROR')
            self._logger.error(
                f'QUERY FOR {query_pack.query_pack_configuration.name} (Execution Id = {query_execution_id}) HAS FAILED'
            )

            self._logger.error(query_execution.status_description)

            self._kinesis.send_error_results(query_pack)

            self._mark_query_pack_sent(query_pack)
            self._mark_query_pack_error(query_pack)
            return

        result = query_pack.fetch_results()

        self._logger.debug('Query Completed:')
        self._logger.debug('Execution Id: %s', result.query_execution.query_execution_id)
        self._logger.debug('Query: %s', result.query_execution.query)
        self._logger.debug('Runtime: %d', result.query_execution.engine_execution_time_in_millis)
        self._logger.debug('Bytes: %d', result.query_execution.data_scanned_in_bytes)
        self._logger.debug('Status: %s', result.query_execution.status)
        self._logger.debug('Reason: %s', result.query_execution.status_description)

        self._kinesis.send_query_results(query_pack)

        self._mark_query_pack_sent(query_pack)

    def _query_pack_already_sent(self, query_pack):
        cache_key = query_pack.unique_id
        cache_entry = self._state_manager.get(cache_key)
        return cache_entry.get('sent_to_streamalert', False)

    def _mark_query_pack_sent(self, query_pack):
        cache_key = query_pack.unique_id
        cache_entry = self._state_manager.get(cache_key)
        cache_entry['sent_to_streamalert'] = True
        self._state_manager.set(cache_key, cache_entry)

    def _mark_query_pack_error(self, query_pack):
        cache_key = query_pack.unique_id
        cache_entry = self._state_manager.get(cache_key)
        cache_entry['error'] = True
        self._state_manager.set(cache_key, cache_entry)
