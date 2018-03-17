"""Define some shared resources."""
import logging
import os
import string


ALERT_PROCESSOR_NAME = 'alert_processor'
ATHENA_PARTITION_REFRESH_NAME = 'athena_partition_refresh'
RULE_PROCESSOR_NAME = 'rule_processor'
NORMALIZATION_KEY = 'streamalert:normalization'

REQUIRED_OUTPUTS = {
    'aws-firehose': {
        'alerts': '{prefix}_streamalert_alert_delivery',
    }
}

def get_required_outputs(prefix=""):
    """Iterates through the required outputs and adds the prefix to them

    Args:
        prefix (str): Prefix for this StreamAlert deployment

    Returns:
        set: Set of required outputs to be applied to an alert
    """
    def _check_fmt(output):
        fmt = list(string.Formatter().parse(output))
        # Make sure there are only 2 parts to the format string. ie:
        # [('', 'prefix', '', None), ('_streamalert_alert_delivery', None, None, None)]
        if len(fmt) != 2:
            return False

        # Do not try to format if the 'prefix' is not the only formatting option
        if fmt[0][1] != 'prefix':
            return False

        return True

    outputs = dict()
    for service, value in REQUIRED_OUTPUTS.iteritems():
        if not isinstance(value, dict):
            continue

        for output, resource in value.iteritems():
            if not _check_fmt(resource):
                continue

            outputs['{}:{}'.format(service, output)] = resource.format(prefix=prefix)

    return outputs


# Create a package level logger to import
LEVEL = os.environ.get('LOGGER_LEVEL', 'INFO').upper()

# Cast integer levels to avoid a ValueError
if LEVEL.isdigit():
    LEVEL = int(LEVEL)

logging.basicConfig(format='%(name)s [%(levelname)s]: %(message)s')
LOGGER = logging.getLogger('StreamAlertShared')
try:
    LOGGER.setLevel(LEVEL)
except (TypeError, ValueError) as err:
    LOGGER.setLevel('INFO')
    LOGGER.error('Defaulting to INFO logging: %s', err)
