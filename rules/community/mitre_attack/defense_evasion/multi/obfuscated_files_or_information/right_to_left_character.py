"""Detection of the right to left override unicode character U+202E in filename or process name."""
from streamalert.shared.rule import rule
from streamalert.shared.normalize import Normalizer


@rule(datatypes=['command', 'filePath', 'processPath', 'fileName'])
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
    rlo = '\u202e'

    commands = Normalizer.get_values_for_normalized_type(rec, 'command')
    for command in commands:
        if isinstance(command, str) and rlo in command:
            return True

    file_paths = Normalizer.get_values_for_normalized_type(rec, 'filePath')
    for file_path in file_paths:
        if isinstance(file_path, str) and rlo in file_path:
            return True

    process_paths = Normalizer.get_values_for_normalized_type(rec, 'processPath')
    for process_path in process_paths:
        if isinstance(process_path, str) and rlo in process_path:
            return True

    file_names = Normalizer.get_values_for_normalized_type(rec, 'fileName')
    for file_name in file_names:
        if isinstance(file_name, str) and rlo in file_name:
            return True

    return False
