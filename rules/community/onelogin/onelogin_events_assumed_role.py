"""Alert on the OneLogin event that a user has assumed the role of someone else."""
from stream_alert.rule_processor.rules_engine import StreamRules

rule = StreamRules.rule

@rule(logs=['onelogin:events'],
      outputs=['aws-s3:sample-bucket',
               'pagerduty:sample-integration'])
def onelogin_events_assumed_role(rec):
    """
    author:       @javutin
    description:  Alert on OneLogin users assuming a different role.
    reference_1:  https://support.onelogin.com/hc/en-us/articles/202123164-Assuming-Users
    reference_2:  https://developers.onelogin.com/api-docs/1/events/event-types
    """
    return rec['event_type_id'] == 3
