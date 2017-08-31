"""Alert on matching IP address from aws access."""
from stream_alert.rule_processor.rules_engine import StreamRules
from helpers.base import fetch_values_by_datatype

rule = StreamRules.rule


@rule(logs=['cloudwatch:events'],
      matchers=[],
      datatypes=['ipv4'],
      outputs=['aws-s3:sample-bucket',
               'pagerduty:sample-integration',
               'slack:sample-channel'])
def cloudtrail_aws_access_by_evil(rec):
    """
    author:           airbnb_csirt
    description:      This is sample rule to get alert by using normalized type
                      "ipaddress".
    """

    results = fetch_values_by_datatype(rec, 'ipv4')

    for result in results:
        if result == '1.1.1.2':
            return True
    return False
