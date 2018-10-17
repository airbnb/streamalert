"""Define some shared resources."""
ALERT_MERGER_NAME = 'alert_merger'
ALERT_PROCESSOR_NAME = 'alert_processor'
ATHENA_PARTITION_REFRESH_NAME = 'athena_partition_refresh'
CLASSIFIER_FUNCTION_NAME = 'classifier'
RULE_PROCESSOR_NAME = 'rule_processor'
RULE_PROMOTION_NAME = 'rule_promotion'
NORMALIZATION_KEY = 'streamalert:normalization'

CLUSTERED_FUNCTIONS = {CLASSIFIER_FUNCTION_NAME, RULE_PROCESSOR_NAME}
