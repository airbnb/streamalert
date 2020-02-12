from streamalert.streamquery import __version__ as streamquery_version

parameters = {
    'command_name': 'StreamQuery (CLI) v{}'.format(streamquery_version),

    'aws_region': 'us-east-1',

    # Configure Logger
    'log_level': 'DEBUG',

    # Configure Athena
    'athena_auth_mode': 'profile',
    'athena_profile': 'csirt2fa',
    'athena_database': 'streamalert',
    'athena_results_bucket': 'aws-athena-query-results-569589067625-us-east-1',

    # Configure Kinesis
    'kinesis_auth_mode': 'profile',
    'kinesis_profile': 'csirt-streamalert-csirt',
    'kinesis_stream': 'airbnb_csirt_stream_alert_kinesis',
}
