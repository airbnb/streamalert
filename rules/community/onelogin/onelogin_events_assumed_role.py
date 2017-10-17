"""Alert on the OneLogin event that a user has assumed the role of someone else."""
from stream_alert.rule_processor.rules_engine import StreamRules

rule = StreamRules.rule

@rule(logs=['onelogin:events'],
      outputs=['aws-s3:sample-bucket',
               'pagerduty:sample-integration'])
def onelogin_events_assumed_role(rec):
    """
    author:       airbnb_csirt
    description:  Alert on OneLogin users assuming a different role.
    reference:    https://developers.onelogin.com/api-docs/1/events/event-types
    playbook:     N/A
    """
    return rec['event_type_id'] == 3
