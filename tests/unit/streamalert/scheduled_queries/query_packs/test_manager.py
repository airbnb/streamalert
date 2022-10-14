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
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from streamalert.scheduled_queries.query_packs.manager import (
    QueryPack, QueryPackExecutionContext, QueryPacksManager,
    QueryPacksManagerFactory)
from streamalert.scheduled_queries.query_packs.parameters import \
    QueryParameterGenerator


class TestQueryPackExecutionContext:
    def __init__(self):
        self._cache = MagicMock(name='cache')
        self._athena = MagicMock(name='athena')
        self._logger = MagicMock(name='logger')
        self._params = MagicMock(name='params')
        self._repo = MagicMock(name='repo')
        self._clock = MagicMock(name='clock')
        self._context = QueryPackExecutionContext(
            cache=self._cache, athena=self._athena, logger=self._logger,
            params=self._params, repository=self._repo, clock=self._clock
        )

    def test_methods(self):
        """StreamQuery - QueryPackExecutionContext - Test methods"""
        assert self._cache == self._context.state_manager
        assert self._athena == self._context.athena_client
        assert self._logger == self._context.logger
        assert self._params == self._context.parameter_generator
        assert self._repo == self._context.query_pack_repository
        assert self._clock == self._context.clock


class TestQueryPack:
    def __init__(self):
        self._config = None
        self._execution = None
        self._query_pack = None

    def setup(self):
        self._config = MagicMock(name='MockedConfiguration')
        self._execution = MagicMock(name='MockedExecutionContext')
        self._query_pack = QueryPack(self._config, self._execution)

    def test_unique(self):
        """StreamQuery - QueryPack - unique_id - hourly"""
        self._config.tags = ['hourly']
        self._config.name = 'test_pack_name'

        assert self._query_pack.unique_id == 'test_pack_name'

    def test_query_pack_configuration(self):
        """StreamQuery - QueryPack - query_pack_configuration"""
        assert self._query_pack.query_pack_configuration == self._config

    def test_load_from_cache(self):
        """StreamQuery - QueryPack - load_from_cache"""
        self._execution.state_manager.has.return_value = True
        self._execution.state_manager.get.return_value = {
            'query_execution_id': '1111-2222-3333-4444'
        }
        self._query_pack.load_from_cache()
        assert self._query_pack.query_execution_id == '1111-2222-3333-4444'
        assert self._query_pack.is_previously_started

    def test_load_from_cache_none(self):
        """StreamQuery - QueryPack - load_from_cache - not in cache"""
        self._execution.state_manager.has.return_value = False
        self._query_pack.load_from_cache()
        assert self._query_pack.query_execution_id is None
        assert not self._query_pack.is_previously_started

    def test_query_execution_before_start(self):
        """StreamQuery - QueryPack - query_execution - before start"""
        assert self._query_pack.query_execution is None

    def test_query_execution_start(self):
        """StreamQuery - QueryPack - query_execution - start"""

        self._config.generate_query.return_value = 'MOCK QUERY STRING'
        self._execution.athena_client.run_async_query.return_value = 'query_id'

        assert self._query_pack.start_query() == 'query_id'

        self._execution.athena_client.run_async_query.assert_called_with('MOCK QUERY STRING')

    def test_query_execution_load(self):
        """StreamQuery - QueryPack - load_query_execution"""

        self._config.generate_query.return_value = 'MOCK QUERY STRING'
        self._execution.athena_client.run_async_query.return_value = 'query_id'

        self._query_pack.start_query()

        mock_execution = MagicMock(name='MockedQueryExecution')
        self._execution.athena_client.get_query_execution.return_value = mock_execution

        assert self._query_pack.load_query_execution() == mock_execution
        assert self._query_pack.query_execution == mock_execution

    def test_fetch_results_done(self):
        """StreamQuery - QueryPack - fetch_results - done"""
        self._config.generate_query.return_value = 'MOCK QUERY STRING'
        self._execution.athena_client.run_async_query.return_value = 'query_id'
        self._query_pack.start_query()

        mock_execution = MagicMock(name='MockedQueryExecution')
        self._execution.athena_client.get_query_execution.return_value = mock_execution
        self._query_pack.load_query_execution()

        mock_execution.is_succeeded.return_value = True
        mocked_res = MagicMock(name='MockedResult')
        self._execution.athena_client.get_query_result.return_value = mocked_res

        assert self._query_pack.fetch_results() == mocked_res

    def test_fetch_results_not_done(self):
        """StreamQuery - QueryPack - fetch_results - not done"""
        self._config.generate_query.return_value = 'MOCK QUERY STRING'
        self._execution.athena_client.run_async_query.return_value = 'query_id'
        self._query_pack.start_query()

        mock_execution = MagicMock(name='MockedQueryExecution')
        self._execution.athena_client.get_query_execution.return_value = mock_execution
        self._query_pack.load_query_execution()

        mock_execution.is_succeeded.return_value = False
        assert self._query_pack.fetch_results() is None


class TestQueryPacksManager:
    def __init__(self):
        self._execution_context = None
        self._manager = None
        self._logger = None

    def setup(self):
        self._execution_context = MagicMock(name='ExecutionContext')
        self._manager = QueryPacksManager(
            self._execution_context
        )

    def test_start_queries(self):
        """StreamQuery - QueryPacksManager - start_queries"""
        logger = MagicMock(name='Logger')
        self._execution_context.logger = logger
        self._execution_context.state_manager.has.return_value = False

        config1 = MagicMock(name='Config1')
        config1.name = 'test_query_pack_name'
        config2 = MagicMock(name='Config2')
        config2.name = 'test_query_pack_name_2'
        self._execution_context.query_pack_repository.get_packs.return_value = [config1, config2]

        self._manager.load_query_configurations()
        self._manager.initialize_query_packs()
        self._manager.start_queries()

        logger.info.assert_any_call(
            'Executing Query Pack "%s"...', 'test_query_pack_name'
        )
        logger.info.assert_any_call(
            'Executing Query Pack "%s"...', 'test_query_pack_name_2'
        )

        assert self._manager.num_queries_still_running == 2

    def test_start_queries_from_cache(self):
        """StreamQuery - QueryPacksManager - start_queries - from cache"""
        logger = MagicMock(name='Logger')
        self._execution_context.logger = logger
        self._execution_context.state_manager.has.return_value = True
        self._execution_context.state_manager.get.return_value = {
            'query_execution_id': 'qwertyuiop'
        }

        config1 = MagicMock(name='Config1')
        config1.name = 'test_query_pack_name'
        config2 = MagicMock(name='Config2')
        config2.name = 'test_query_pack_name_2'
        self._execution_context.query_pack_repository.get_packs.return_value = [config1, config2]

        self._manager.load_query_configurations()
        self._manager.initialize_query_packs()
        self._manager.start_queries()

        logger.debug.assert_any_call(
            'Existing Query Execution exists for "%s": [%s]',
            'test_query_pack_name',
            'qwertyuiop'
        )


class TestQueryParameterGenerator:
    def __init__(self):
        self._logger = None
        self._generator = None  # type: QueryParameterGenerator

    def setup(self):
        self._logger = MagicMock(name='Logger')
        clock = MagicMock(name='Clock')
        clock.now = datetime(
            year=2019, month=1, day=1, hour=1, minute=1, second=1, tzinfo=timezone.utc
        )
        self._generator = QueryParameterGenerator(self._logger, clock)

    def test_generate_utcdatehour_minus7day(self):
        """StreamQuery - QueryParameterGenerator - generate - utcdatehour_minus7day"""
        assert self._generator.generate('utcdatehour_minus7day') == '2018-12-25-01'

    def test_generate_utcdatehour_minus1hour(self):
        """StreamQuery - QueryParameterGenerator - generate - utcdatehour_minus1hour"""
        assert self._generator.generate('utcdatehour_minus1hour') == '2019-01-01-00'

    def test_generate_utctimestamp_minus1hour(self):
        """StreamQuery - QueryParameterGenerator - generate - utctimestamp_minus1hour"""
        assert self._generator.generate('utctimestamp_minus1hour') == '1546300861'

    def test_generate_utcdatehour_minus2hour(self):
        """StreamQuery - QueryParameterGenerator - generate - utcdatehour_minus2hour"""
        assert self._generator.generate('utcdatehour_minus2hour') == '2018-12-31-23'

    def test_generate_utcdatehour_minus1day(self):
        """StreamQuery - QueryParameterGenerator - generate - utcdatehour_minus1day"""
        assert self._generator.generate('utcdatehour_minus1day') == '2018-12-31-01'

    def test_generate_utcdatehour_minus2day(self):
        """StreamQuery - QueryParameterGenerator - generate - utcdatehour_minus2day"""
        assert self._generator.generate('utcdatehour_minus2day') == '2018-12-30-01'

    def test_generate_utcdatehour(self):
        """StreamQuery - QueryParameterGenerator - generate - utcdatehour"""
        assert self._generator.generate('utcdatehour') == '2019-01-01-01'

    def test_generate_utctimestamp(self):
        """StreamQuery - QueryParameterGenerator - generate - utctimestamp"""
        assert self._generator.generate('utctimestamp') == '1546304461'

    def test_generate_unsupported(self):
        """StreamQuery - QueryParameterGenerator - generate - unsupported"""
        self._generator.generate('unsupported')

        self._logger.error.assert_called_with(
            'Parameter generator does not know how to handle "unsupported"'
        )

    def test_generate_advanced_function(self):
        """StreamQuery - QueryParameterGenerator - generate_advanced - Function"""
        def thing(date):
            return date.strftime('%Y-%m-%d-%H-%I-%S')
        assert self._generator.generate_advanced('thing', thing) == '2019-01-01-01-01-01'

    def test_generate_advanced_nothing(self):
        """StreamQuery - QueryParameterGenerator - generate_advanced - Nothing"""
        assert self._generator.generate_advanced('utctimestamp', None) == '1546304461'


@patch('streamalert.scheduled_queries.query_packs.manager.QueryPacksManager')
def test_new_manager(constructor_spy):
    """StreamQuery - QueryPacksManagerFactory - new_manager"""
    context = MagicMock(name='MockedExecutionContext')
    factory = QueryPacksManagerFactory(context)

    instance = MagicMock(name='MockedManager')
    constructor_spy.return_value = instance

    assert factory.new_manager() == instance

    constructor_spy.assert_called_with(context)
