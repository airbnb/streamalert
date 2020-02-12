"""
This file is the entry point for AWS Lambda.
"""
from datetime import datetime

from streamalert.streamquery.command.processor import CommandProcessor
from streamalert.streamquery.config.services import configure_container
from streamalert.streamquery.container.container import ServiceContainer
from streamalert.streamquery.state.state_manager import StepFunctionStateManager, StateManager
from streamalert.streamquery.config.lambda_conf import parameters


def handler(event, context):  # pylint: disable=unused-argument
    """Ensure the Lambda function's Handler is set to: 'lambda.handler' """

    # Boot the service container
    service_container = ServiceContainer(parameters)
    configure_container(service_container)

    # Start the function
    logger = service_container.get('logger')
    logger.info('Running StreamQuery lambda handler')
    logger.debug(
        'Invocation event: %s', event
    )
    logger.debug(
        'ServiceContainer parameters: %s', parameters
    )

    # Load up any prior state from the event passed in from the StepFunction
    state_manager_loader = StepFunctionStateManager(service_container.get('state_manager'), logger)
    state_manager_loader.load_from_step_function_event(event)

    # Wind the clock as part of the setup operation, if necessary
    state_manager = service_container.get('state_manager')  # type: StateManager
    clock = service_container.get('clock')
    isotime = state_manager.get('streamquery_configuration', {}).get('clock', False)
    if isotime:
        clock_datetime = datetime.strptime(isotime, "%Y-%m-%dT%H:%M:%SZ")
        clock.time_machine(clock_datetime)
        logger.info('Winding clock to %s...', clock.now)
    else:
        logger.warning('No clock configuration provided. Defaulting to %s', clock.now)

    # Execute a single pass of the StreamQuery runtime
    processor = service_container.get('command_processor')  # type: CommandProcessor
    done = processor.nonblocking_single_pass()

    # Set the updated state into the response
    #   The step function as-written currently looks specifically for $.done and $.continue and
    #   expects both of them to be present AND to be adopt exact numeric values
    response = {
        'done': 1 if done else 0,
        'continue': 1,
    }
    state_manager_loader.write_to_step_function_response(response)

    return response
