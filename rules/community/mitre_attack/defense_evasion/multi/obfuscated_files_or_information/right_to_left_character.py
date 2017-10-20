"""Detection of the right to left override unicode character U+202E in filename or process name."""
from helpers.base import fetch_values_by_datatype
from stream_alert.rule_processor.rules_engine import StreamRules

rule = StreamRules.rule

@rule(datatypes=['command', 'filePath', 'processPath', 'fileName'],
      outputs=['aws-s3:sample-bucket', 'pagerduty:sample-integration'])
def right_to_left_character(rec):
    """
    author:           @javutin
    description:      Malicious files can be disguised by using a encoding trick that uses the
                      unicode character U+202E, also known as right-to-left-override (RLO).
                      The trick hides a potentially malicious extension and makes them appear
                      harmless.

    reference:        https://krebsonsecurity.com/2011/09/right-to-left-override-aids-email-attacks
    playbook:         (a) verify the file has an RTLO character and that the file is malicious
    ATT&CK Tactic:    Defense Evasion
    ATT&CK Technique: Obfuscated Files or Information
    ATT&CK URL:       https://attack.mitre.org/wiki/Technique/T1027
    """

    # Unicode character U+202E, right-to-left-override (RLO)
    rlo = u'\u202e'

    commands = fetch_values_by_datatype(rec, 'command')
    for command in commands:
        if isinstance(command, unicode) and rlo in command:
            return True

    file_paths = fetch_values_by_datatype(rec, 'filePath')
    for file_path in file_paths:
        if isinstance(file_path, unicode) and rlo in file_path:
            return True

    process_paths = fetch_values_by_datatype(rec, 'processPath')
    for process_path in process_paths:
        if isinstance(process_path, unicode) and rlo in process_path:
            return True

    file_names = fetch_values_by_datatype(rec, 'fileName')
    for file_name in file_names:
        if isinstance(file_name, unicode) and rlo in file_name:
            return True

    return False
