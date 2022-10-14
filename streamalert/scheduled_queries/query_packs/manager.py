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
import json
from logging import Logger

from streamalert.scheduled_queries.handlers.athena import AthenaClient
from streamalert.scheduled_queries.query_packs.configuration import (
    QueryPackConfiguration, QueryPackRepository)
from streamalert.scheduled_queries.query_packs.parameters import \
    QueryParameterGenerator
from streamalert.scheduled_queries.state.state_manager import StateManager
from streamalert.scheduled_queries.support.clock import Clock


class QueryPackExecutionContext:
    """A convenience service bundle for multiple services related to querying"""
    def __init__(self,
                 cache=None,
                 athena=None,
                 logger=None,
                 params=None,
                 repository=None,
                 clock=None):
        self._cache = cache  # type: StateManager
        self._athena = athena  # type: AthenaClient
        self._logger = logger  # type: Logger
        self._params = params  # type: QueryParameterGenerator
        self._repo = repository  # type: QueryPackRepository
        self._clock = clock  # type: Clock

    @property
    def state_manager(self):
        return self._cache

    @property
    def athena_client(self):
        return self._athena

    @property
    def logger(self):
        return self._logger

    @property
    def parameter_generator(self):
        return self._params

    @property
    def query_pack_repository(self):
        return self._repo

    @property
    def clock(self):
        return self._clock


class QueryPack:
    """An encapsulation of both the query configuration as well as the intent to execute it

    This "pack" includes any additional state, parameters, and other stuff.
    """
    def __init__(self, query_pack_configuration, execution_context):
        self._configuration = query_pack_configuration  # type: QueryPackConfiguration
        self._execution_context = execution_context

        self._query_execution = None
        self._query_execution_id = None
        self._query_result = None

        if isinstance(self._configuration.query_parameters, dict):
            self._query_parameters = {
                param:
                self._execution_context.parameter_generator.generate_advanced(param, configuration)
                for param, configuration in self._configuration.query_parameters.items()
            }
        elif isinstance(self._configuration.query_parameters, list):
            self._query_parameters = {
                param: self._execution_context.parameter_generator.generate(param)
                for param in self._configuration.query_parameters
            }
        else:
            # not intended to be reached
            self._query_parameters = {}

        self._query_string = None

    @property
    def unique_id(self):
        return self._configuration.name

    @property
    def query_pack_configuration(self):
        """
        Returns:
             QueryPackConfiguration
        """
        return self._configuration

    @property
    def query_execution(self):
        """
        Returns:
             AthenaQueryExecution
        """
        return self._query_execution

    @property
    def query_execution_id(self):
        return self._query_execution_id

    @property
    def query_result(self):
        return self._query_result

    @property
    def is_previously_started(self):
        return self._query_execution_id is not None

    @property
    def query_parameters(self):
        return self._query_parameters

    @property
    def query_string(self):
        return self._query_string

    def load_from_cache(self):
        cache_key = self.unique_id
        if self._execution_context.state_manager.has(cache_key):
            entry = self._execution_context.state_manager.get(cache_key)
            query_execution_id = entry['query_execution_id']
            self._query_execution_id = query_execution_id

    def start_query(self):
        """Kicks off the current query to Athena, returning a query execution id

        Calls to this method internally modify ths query pack, setting the query_execution_id
        property. Calling this method when is_previous_started=True will do not thing.
        """
        if self.is_previously_started:
            return None

        self._query_execution_id = self._execution_context.athena_client.run_async_query(
            self.generate_query_string())
        self.save_to_cache()
        return self._query_execution_id

    def load_query_execution(self):
        """Refreshes the query_execution property of this query pack

        Returns:
            AthenaQueryExecution
        """
        if not self.is_previously_started:
            return None

        self._query_execution = self._execution_context.athena_client.get_query_execution(
            self._query_execution_id)
        return self._query_execution

    def fetch_results(self):
        """Refreshes the query_result property of this query pack

        Returns:
            AthenaQueryResult
        """
        if not self._query_execution.is_succeeded():
            return None

        self._query_result = self._execution_context.athena_client.get_query_result(
            self._query_execution)
        return self._query_result

    def save_to_cache(self):
        entry = {
            'query_execution_id': self._query_execution_id,
            # 'query_string': self.generate_query_string(),
        }

        self._execution_context.state_manager.set(self.unique_id, entry)

    def generate_query_string(self):
        params = self._query_parameters
        self._execution_context.logger.debug('Generated Parameters: {}'.format(
            json.dumps(params, indent=2)))
        self._query_string = self._configuration.generate_query(**params)
        return self._query_string


class QueryPacksManagerFactory:
    """A factory service for generating QueryPacksManager instances"""
    def __init__(self, execution_context):
        self._execution_context = execution_context  # type: QueryPackExecutionContext

    def new_manager(self):
        """
        Return:
             QueryPacksManager
        """
        manager = QueryPacksManager(self._execution_context)
        manager.load_query_configurations()

        return manager


class QueryPacksManager:
    """This class manages multiple query packs that are firing off simultaneously

    This class is not a service--it is a stateful container for QueryPacks, which themselves
    can be stateful.
    """
    def __init__(self, execution_context):
        self._execution_context = execution_context

        self._query_configs = []  # type: list[QueryPackConfiguration]

        self._query_packs = []  # type: list[QueryPack]

    def load_query_configurations(self):
        repo_packs = self._execution_context.query_pack_repository.get_packs()

        # Tags are an inclusive filter
        # If no tags are provided, then it includes all packs
        # If multiple tags are provided, then only the packs that contain ALL OF THE TAGS
        # will be run
        configured_tags = self._execution_context.state_manager.get('streamquery_configuration',
                                                                    {}).get('tags', [])

        for tag in configured_tags:
            repo_packs = [pack for pack in repo_packs if tag in pack.tags]

        self._query_configs = repo_packs

    def initialize_query_packs(self):
        """Sets up query packs for this manager.

        QueryPacks are a list of queries that this manager is intended to manage.
        """

        self._query_packs = []

        for pack_config in self._query_configs:
            query_pack = QueryPack(pack_config, self._execution_context)
            query_pack.load_from_cache()

            self._query_packs.append(query_pack)

    def start_queries(self):
        """Kicks off all query packs, if necessary

        This method is idempotent.
        """
        for query_pack in self._query_packs:
            self._kickoff_query(query_pack)

    @property
    def query_packs(self):
        return self._query_packs

    @property
    def finished_query_packs(self):
        return [
            query for query in self._query_packs
            if not query.load_query_execution().is_still_running()
        ]

    @property
    def num_registered_queries(self):
        """This property is the number of configured queries, NOT the number of running ones"""
        return len(self._query_configs)

    @property
    def all_queries_finished(self):
        return self.num_queries_still_running == 0

    @property
    def num_queries_still_running(self):
        return len(self.query_packs) - len(self.finished_query_packs)

    def _kickoff_query(self, query_pack):
        """Begins executing a query, given the QueryPackConfiguration

        Args:
            query_pack (QueryPack)

        Returns:
            QueryPack
        """
        if query_pack.is_previously_started:
            self._execution_context.logger.debug('Existing Query Execution exists for "%s": [%s]',
                                                 query_pack.query_pack_configuration.name,
                                                 query_pack.query_execution_id)
            return query_pack

        self._execution_context.logger.info('Executing Query Pack "%s"...',
                                            query_pack.query_pack_configuration.name)

        query_pack.start_query()

        return query_pack
