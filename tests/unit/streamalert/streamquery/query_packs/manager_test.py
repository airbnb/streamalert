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
from mock import MagicMock
from nose.tools import assert_equals, assert_false, assert_true

from streamalert.streamquery.query_packs.manager import (
    QueryPack, QueryPacksManager, QueryParameterGenerator
)


class TestQueryPack:
    def __init__(self):
        self._config = None
        self._execution = None
        self._query_pack = None

    def setup(self):
        self._config = MagicMock(name='MockedConfiguration')
        self._execution = MagicMock(name='MockedExecutionContext')
        self._query_pack = QueryPack(self._config, self._execution)

    def test_unique_id_hourly(self):
        """QueryPack - unique_id - hourly"""
        self._config.tags = ['hourly']
        self._config.name = 'test_pack_name'

        self._execution.clock.now = datetime(year=2000, month=1, day=1)

        assert_equals(self._query_pack.unique_id, 'test_pack_name:2000-01-01-00')

    def test_unique_id_hourly_2(self):
        """QueryPack - unique_id - hourly #2"""
        self._config.tags = ['hourly']
        self._config.name = 'test_pack_name2'

        self._execution.clock.now = datetime(year=2000, month=1, day=1, hour=5)

        assert_equals(self._query_pack.unique_id, 'test_pack_name2:2000-01-01-05')

    def test_unique_id_daily_1(self):
        """QueryPack - unique_id - daily"""
        self._config.tags = ['daily']
        self._config.name = 'test_pack_name'

        self._execution.clock.now = datetime(year=2000, month=1, day=1)

        assert_equals(self._query_pack.unique_id, 'test_pack_name:2000-01-01')

    def test_unique_id_daily_2(self):
        """QueryPack - unique_id - daily #2"""
        self._config.tags = ['daily']
        self._config.name = 'test_pack_name2'

        self._execution.clock.now = datetime(year=2000, month=1, day=1, hour=5)

        assert_equals(self._query_pack.unique_id, 'test_pack_name2:2000-01-01')

    def test_query_pack_configuration(self):
        """QueryPack - query_pack_configuration"""
        assert_equals(self._query_pack.query_pack_configuration, self._config)

    def test_load_from_cache(self):
        """QueryPack - load_from_cache"""
        self._execution.state_manager.has.return_value = True
        self._execution.state_manager.get.return_value = {
            'query_execution_id': '1111-2222-3333-4444'
        }
        self._query_pack.load_from_cache()
        assert_equals(self._query_pack.query_execution_id, '1111-2222-3333-4444')
        assert_true(self._query_pack.is_previously_started)

    def test_load_from_cache_none(self):
        """QueryPack - load_from_cache - not in cache"""
        self._execution.state_manager.has.return_value = False
        self._query_pack.load_from_cache()
        assert_equals(self._query_pack.query_execution_id, None)
        assert_false(self._query_pack.is_previously_started)


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
        """QueryPacksManager - start_queries"""
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

        assert_equals(self._manager.num_queries_still_running, 2)

    def test_start_queries_from_cache(self):
        """QueryPacksManager - start_queries - from cache"""
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
        """QueryParameterGenerator - generate - utcdatehour_minus7day"""
        assert_equals(self._generator.generate('utcdatehour_minus7day'), '2018-12-25-01')

    def test_generate_utcdatehour_minus1hour(self):
        """QueryParameterGenerator - generate - utcdatehour_minus1hour"""
        assert_equals(self._generator.generate('utcdatehour_minus1hour'), '2019-01-01-00')

    def test_generate_utctimestamp_minus1hour(self):
        """QueryParameterGenerator - generate - utctimestamp_minus1hour"""
        assert_equals(self._generator.generate('utctimestamp_minus1hour'), '1546300861')

    def test_generate_utcdatehour_minus2hour(self):
        """QueryParameterGenerator - generate - utcdatehour_minus2hour"""
        assert_equals(self._generator.generate('utcdatehour_minus2hour'), '2018-12-31-23')

    def test_generate_utcdatehour_minus1day(self):
        """QueryParameterGenerator - generate - utcdatehour_minus1day"""
        assert_equals(self._generator.generate('utcdatehour_minus1day'), '2018-12-31-01')

    def test_generate_utcdatehour_minus2day(self):
        """QueryParameterGenerator - generate - utcdatehour_minus2day"""
        assert_equals(self._generator.generate('utcdatehour_minus2day'), '2018-12-30-01')

    def test_generate_utcdatehour(self):
        """QueryParameterGenerator - generate - utcdatehour"""
        assert_equals(self._generator.generate('utcdatehour'), '2019-01-01-01')

    def test_generate_utctimestamp(self):
        """QueryParameterGenerator - generate - utctimestamp"""
        assert_equals(self._generator.generate('utctimestamp'), '1546304461')

    def test_generate_unsupported(self):
        """QueryParameterGenerator - generate - unsupported"""
        self._generator.generate('unsupported')

        self._logger.error.assert_called_with(
            'Parameter generator does not know how to handle "unsupported"'
        )
