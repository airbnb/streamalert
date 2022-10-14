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

from streamalert.scheduled_queries.query_packs.configuration import (
    QueryPackConfiguration, QueryPackRepository)


class TestConfiguration:

    @staticmethod
    def test_basic_stuff():
        """StreamQuery - QueryPackConfiguration - basic stuff"""
        config = QueryPackConfiguration(
            name='bubblebumblebaddabbabblerabblebarrelmumble',
            query='SELECT * FROM knowhere',
            params=[],
            description='yoo hoo and a bottle of rum',
            tags=['tag1', 'tag2']
        )

        assert config.name == 'bubblebumblebaddabbabblerabblebarrelmumble'
        assert config.query_template == 'SELECT * FROM knowhere'
        assert config.query_parameters == []
        assert config.description == 'yoo hoo and a bottle of rum'
        assert config.tags == ['tag1', 'tag2']

    @staticmethod
    def test_query_construction():
        """StreamQuery - QueryPackConfiguration - generate_query"""
        config = QueryPackConfiguration(
            name='helloworld',
            query="SELECT * FROM helloworld WHERE dt = '{date}'",
            params=['date'],
            description='yoo hoo and a bottle of rum',
            tags=['tag1', 'tag2']
        )

        assert (config.generate_query(date='2000-01-01') ==
                "SELECT * FROM helloworld WHERE dt = '2000-01-01'")


class TestQueryPackRepository:

    @staticmethod
    def test_load_and_get_packs():
        """StreamQuery - QueryPackRepository - get_packs"""
        QueryPackRepository.load_packs(['scheduled_queries/'])

        assert len(QueryPackRepository.get_packs()) >= 1
