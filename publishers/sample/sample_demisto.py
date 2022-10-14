"""
Batch of example publishers usable with Demisto.
"""
from streamalert.shared.publisher import Register


@Register
def demisto_classification(alert, publication):
    """
    This publisher appropriately sets the demisto incident type and playbook.

    It first looks into the alert's context for the "demisto" key, where individual rules can
    explcitly specify the desired classification traits of the output alert.
    """

    # If a rule explicitly states Demisto information with the alert context, obey that
    # The convention to follow is any key in this dict (example, "incident_type") is mapped
    # directly onto the Demisto output magic keys (example, @demisto.incident_type)
    if 'demisto' in alert.context:
        for key, value in alert.context['demisto'].items():
            output_key = f'@demisto.{key}'
            publication[output_key] = value

        return publication

    # If no context was explicitly declared, then we default to our global rules
    for code in GLOBAL_CLASSIFIERS:
        if payload := code(alert):
            for key, value in payload:
                output_key = f'@demisto.{key}'
                publication[output_key] = value

            return publication

    # Else, nothing
    return publication


def _any_rule_with_demisto(alert):
    if alert.rule_name.contains('sample'):
        return {
            'incident_type': 'Sample Alert',
            'playbook': 'Sample Playbook',
        }

    return False


# The GLOBAL_CLASSIFIERS is an array of functions. Any function that returns a truthy value is
# considered to be a "match". This value must be a dict, and the keys on the dict map directly
# onto the Demisto output magic keys (e.g. "incident_type" -> "@demisto.incident_type")
GLOBAL_CLASSIFIERS = [_any_rule_with_demisto]
