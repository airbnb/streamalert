import logging

import boto3
from botocore import client as botocore_client
from botocore.exceptions import ProfileNotFound

from streamalert.streamquery.command.processor import CommandProcessor
from streamalert.streamquery.container.container import ServiceDefinition
from streamalert.streamquery.handlers.athena import AthenaClient
from streamalert.streamquery.query_packs.configuration import QueryPackRepository
from streamalert.streamquery.query_packs.manager import (
    QueryPackExecutionContext,
    QueryPacksManagerFactory,
    QueryParameterGenerator,
)
from streamalert.streamquery.state.state_manager import StateManager
from streamalert.streamquery.streamalert.kinesis import KinesisClient
from streamalert.streamquery.support.clock import Clock


# pylint: disable=too-many-statements
def configure_container(container):
    """Configures the container

    Params:
        container (ServiceContainer)
    """

    def make_command_processor(_container):
        return CommandProcessor(
            logger=_container.get('logger'),
            kinesis=_container.get('streamalert_forwarder'),
            state_manager=_container.get('state_manager'),
            manager_factory=_container.get('query_pack_manager_factory')
        )

    def make_logger(_container):
        logger = logging.getLogger(_container.get_parameter('command_name'))
        logger.setLevel(_container.get_parameter('log_level'))
        logging.basicConfig(
            format='%(name)s [%(levelname)s]: [%(module)s.%(funcName)s] %(message)s'
        )
        return logger

    def make_kinesis(_container):
        return KinesisClient(
            logger=_container.get('logger'),
            client=_container.get('boto3_kinesis_client'),
            kinesis_stream=_container.get_parameter('kinesis_stream')
        )

    def make_cache(_container):
        cache = StateManager(
            logger=_container.get('logger')
        )

        return cache

    def make_athena(_container):
        return AthenaClient(
            logger=_container.get('logger'),
            client=_container.get('boto3_athena_client'),
            database=_container.get_parameter('athena_database'),
            results_bucket=_container.get_parameter('athena_results_bucket')
        )

    def make_param_generator(_container):
        return QueryParameterGenerator(_container.get('logger'), _container.get('clock'))

    def make_query_pack_repo(_):
        repo = QueryPackRepository
        repo.load_packs()
        return repo

    def make_query_pack_factory(_container):
        return QueryPacksManagerFactory(
            _container.get('query_pack_execution_context')
        )

    def make_execution_context(_container):
        return QueryPackExecutionContext(
            cache=_container.get('state_manager'),
            athena=_container.get('athena'),
            logger=_container.get('logger'),
            params=_container.get('query_parameter_generator'),
            repository=_container.get('query_pack_repository'),
            clock=_container.get('clock')
        )

    def make_clock(_):
        return Clock()

    def make_boto3_athena_client(_container):
        region = _container.get_parameter('aws_region')
        logger = _container.get('logger')

        config = botocore_client.Config(
            connect_timeout=5,
            read_timeout=5,
            region_name=region
        )

        session_kwargs = {}
        auth_mode = _container.get_parameter('athena_auth_mode')
        if auth_mode == 'key':
            session_kwargs = {
                'aws_access_key_id': _container.get_parameter('athena_key_id'),
                'aws_secret_access_key': _container.get_parameter('athena_secret'),
                'aws_session_token': _container.get_parameter('athena_token'),
            }
        elif auth_mode == 'profile':
            session_kwargs = {
                'profile_name': _container.get_parameter('athena_profile')
            }
        elif auth_mode == 'iam_role':
            # Trust the Lambda role to do it correctly.
            pass
        else:
            logger.error('Unrecognized Athena client authentication mode: {}'.format(auth_mode))

        try:
            session = boto3.Session(**session_kwargs)
            return session.client(
                'athena',
                config=config,
            )
        except ProfileNotFound:
            logger.error('AWS Athena Connection via Profile Failed')

    def make_boto3_kinesis_client(_container):
        region = _container.get_parameter('aws_region')
        logger = _container.get('logger')

        config = botocore_client.Config(
            connect_timeout=5,
            read_timeout=5,
            region_name=region
        )

        session_kwargs = {}
        auth_mode = _container.get_parameter('kinesis_auth_mode')
        if auth_mode == 'key':
            session_kwargs = {
                'aws_access_key_id': _container.get_parameter('kinesis_key_id'),
                'aws_secret_access_key': _container.get_parameter('kinesis_secret'),
            }
        elif auth_mode == 'profile':
            session_kwargs = {
                'profile_name': _container.get_parameter('kinesis_profile')
            }
        elif auth_mode == 'iam_role':
            # Trust the Lambda role to do it correctly.
            pass
        else:
            logger.error('Unrecognized Kinesis client authentication mode: {}'.format(auth_mode))

        try:
            session = boto3.Session(**session_kwargs)
            return session.client('kinesis', config=config)
        except ProfileNotFound:
            logger.error('AWS Kinesis Connection via Profile Failed')

    container.register(ServiceDefinition('command_processor', make_command_processor))
    container.register(ServiceDefinition('logger', make_logger))
    container.register(ServiceDefinition('streamalert_forwarder', make_kinesis))
    container.register(ServiceDefinition('state_manager', make_cache))
    container.register(ServiceDefinition('athena', make_athena))
    container.register(ServiceDefinition('query_parameter_generator', make_param_generator))
    container.register(ServiceDefinition('query_pack_repository', make_query_pack_repo))
    container.register(ServiceDefinition('query_pack_manager_factory', make_query_pack_factory))
    container.register(ServiceDefinition('query_pack_execution_context', make_execution_context))
    container.register(ServiceDefinition('clock', make_clock))
    container.register(ServiceDefinition('boto3_athena_client', make_boto3_athena_client))
    container.register(ServiceDefinition('boto3_kinesis_client', make_boto3_kinesis_client))
