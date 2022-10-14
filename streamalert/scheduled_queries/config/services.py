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
import logging

import boto3
from botocore import client as botocore_client
from botocore.exceptions import ProfileNotFound

from streamalert.scheduled_queries.command.processor import CommandProcessor
from streamalert.scheduled_queries.config.lambda_conf import \
    get_streamquery_env_vars
from streamalert.scheduled_queries.container.container import (
    ServiceContainer, ServiceDefinition)
from streamalert.scheduled_queries.handlers.athena import AthenaClient
from streamalert.scheduled_queries.query_packs.configuration import \
    QueryPackRepository
from streamalert.scheduled_queries.query_packs.manager import (
    QueryPackExecutionContext, QueryPacksManagerFactory,
    QueryParameterGenerator)
from streamalert.scheduled_queries.state.state_manager import (
    StateManager, StepFunctionStateManager)
from streamalert.scheduled_queries.streamalert.kinesis import KinesisClient
from streamalert.scheduled_queries.support.clock import Clock
from streamalert.shared.config import load_config


# FIXME (Ryxias)
#   Eventually we should get rid of the ServiceContainer. This pattern isn't really in the spirit
#   of StreamAlert and is a relic from when StreamQuery was a separately maintained project.
class ApplicationServices:
    def __init__(self):
        # Boot the service container
        self._service_container = ServiceContainer(get_streamquery_env_vars())
        configure_container(self._service_container)

    @property
    def logger(self):
        return self._service_container.get('logger')

    @property
    def command_processor(self):
        return self._service_container.get('command_processor')

    @property
    def state_manager(self):
        return self._service_container.get('state_manager')

    @property
    def clock(self):
        return self._service_container.get('clock')

    def create_step_function_state_manager(self):
        return StepFunctionStateManager(self.state_manager, self.logger, self.clock)


# pylint: disable=too-many-statements
def configure_container(container):
    """Configures the container

    Params:
        container (ServiceContainer)
    """
    container.register(ServiceDefinition('command_processor', _make_command_processor))
    container.register(ServiceDefinition('logger', _make_logger))
    container.register(ServiceDefinition('streamalert_forwarder', _make_kinesis))
    container.register(ServiceDefinition('state_manager', _make_cache))
    container.register(ServiceDefinition('athena', _make_athena))
    container.register(ServiceDefinition('query_parameter_generator', _make_param_generator))
    container.register(ServiceDefinition('query_pack_repository', _make_query_pack_repo))
    container.register(ServiceDefinition('query_pack_manager_factory', _make_query_pack_factory))
    container.register(ServiceDefinition('query_pack_execution_context', _make_execution_context))
    container.register(ServiceDefinition('clock', _make_clock))
    container.register(ServiceDefinition('boto3_athena_client', _make_boto3_athena_client))
    container.register(ServiceDefinition('boto3_kinesis_client', _make_boto3_kinesis_client))
    container.register(ServiceDefinition('config', _load_config))


def _load_config(_):
    return load_config()


def _make_command_processor(container):
    return CommandProcessor(logger=container.get('logger'),
                            kinesis=container.get('streamalert_forwarder'),
                            state_manager=container.get('state_manager'),
                            manager_factory=container.get('query_pack_manager_factory'))


def _make_logger(container):
    logger = logging.getLogger(container.get_parameter('command_name'))
    logger.setLevel(container.get_parameter('log_level').upper())
    logging.basicConfig(format='%(name)s [%(levelname)s]: [%(module)s.%(funcName)s] %(message)s')
    return logger


def _make_kinesis(container):
    return KinesisClient(logger=container.get('logger'),
                         client=container.get('boto3_kinesis_client'),
                         kinesis_stream=container.get_parameter('kinesis_stream'))


def _make_cache(container):
    return StateManager(logger=container.get('logger'))


def _make_athena(container):
    return AthenaClient(logger=container.get('logger'),
                        client=container.get('boto3_athena_client'),
                        database=container.get_parameter('athena_database'),
                        results_bucket=container.get_parameter('athena_results_bucket'))


def _make_param_generator(container):
    return QueryParameterGenerator(container.get('logger'), container.get('clock'))


def _make_query_pack_repo(container):
    repo = QueryPackRepository

    config = container.get('config')
    query_directories = list(config['global']['general'].get('scheduled_query_locations', []))

    repo.load_packs(query_directories)
    return repo


def _make_query_pack_factory(container):
    return QueryPacksManagerFactory(container.get('query_pack_execution_context'))


def _make_execution_context(container):
    return QueryPackExecutionContext(cache=container.get('state_manager'),
                                     athena=container.get('athena'),
                                     logger=container.get('logger'),
                                     params=container.get('query_parameter_generator'),
                                     repository=container.get('query_pack_repository'),
                                     clock=container.get('clock'))


def _make_clock(_):
    return Clock()


def _make_boto3_athena_client(container):
    region = container.get_parameter('aws_region')
    logger = container.get('logger')

    config = botocore_client.Config(connect_timeout=5, read_timeout=5, region_name=region)

    session_kwargs = {}
    try:
        session = boto3.Session(**session_kwargs)
        return session.client(
            'athena',
            config=config,
        )
    except ProfileNotFound:
        logger.error('AWS Athena Connection via Profile Failed')


def _make_boto3_kinesis_client(container):
    region = container.get_parameter('aws_region')
    logger = container.get('logger')

    config = botocore_client.Config(connect_timeout=5, read_timeout=5, region_name=region)

    session_kwargs = {}
    try:
        session = boto3.Session(**session_kwargs)
        return session.client('kinesis', config=config)
    except ProfileNotFound:
        logger.error('AWS Kinesis Connection via Profile Failed')
