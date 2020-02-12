import os
from streamalert.streamquery import __version__ as streamquery_version

parameters = {
    'command_name': 'StreamQuery (Lambda) v{}'.format(streamquery_version),

    'aws_region': os.environ['REGION'],

    # Configure Logger
    'log_level': 'INFO',  # Change to DEBUG for additional verbosity

    # Configure Athena
    'athena_auth_mode': 'iam_role',
    'athena_database': os.environ['ATHENA_DATABASE'],
    'athena_results_bucket': os.environ['ATHENA_RESULTS_BUCKET'],

    # Configure Kinesis
    'kinesis_auth_mode': 'iam_role',
    'kinesis_stream': os.environ['KINESIS_STREAM'],
}
