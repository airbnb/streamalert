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
import pytest

from streamalert.scheduled_queries.config.services import configure_container
from streamalert.scheduled_queries.container.container import ServiceContainer


class TestServiceContainer:
    @staticmethod
    def test_get_parameter():
        """StreamQuery - ServiceContainer - get_parameter"""
        container = ServiceContainer({'a': 'b'})
        assert container.get_parameter('a') == 'b'

    @staticmethod
    def test_get_parameter_raise():
        """StreamQuery - ServiceContainer - get_parameter - raises on invalid"""
        container = ServiceContainer({'a': 'b'})
        pytest.raises(ValueError, container.get_parameter, 'q')

    @staticmethod
    def test_get_logger():
        """StreamQuery - ServiceContainer - get - logger"""
        container = ServiceContainer({
            'command_name': "the_test",
            'log_level': 'INFO'
        })
        configure_container(container)

        assert container.get('logger')

    @staticmethod
    def test_get_logger_raises_on_missing_params():
        """StreamQuery - ServiceContainer - get - logger - raises"""
        container = ServiceContainer({})
        configure_container(container)

        pytest.raises(ValueError, container.get, 'logger')

    @staticmethod
    def test_get_everything_else():
        """StreamQuery - ServiceContainer - get - other"""
        container = ServiceContainer({
            'command_name': "the_test",
            'log_level': 'INFO',
            'aws_region': 'us-nowhere-1',

            'kinesis_auth_mode': 'iam_role',
            'kinesis_stream': 'aaaa',

            'athena_auth_mode': 'iam_role',
            'athena_database': 'test',
            'athena_results_bucket': 'test',
        })
        configure_container(container)

        assert container.get('streamalert_forwarder')
        assert container.get('athena')
        assert container.get('query_parameter_generator')
        assert container.get('query_pack_repository')
        assert container.get('query_pack_manager_factory')
        assert container.get('boto3_kinesis_client')
        assert container.get('boto3_athena_client')

    @staticmethod
    def test_get_raises_on_missing():
        """StreamQuery - ServiceContainer - get - other"""
        container = ServiceContainer({})
        configure_container(container)

        pytest.raises(ValueError, container.get, 'ablsadflj')
