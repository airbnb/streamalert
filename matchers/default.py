"""
Matchers extract common logic into helpers that can be referenced in
multiple rules.  For example, if we write an osquery rule that
is specific for the `prod` environment, we can define a matcher
and add it to our rules' `matchers` keyword argument:

from matchers import default

@rule('root_logins', logs=['osquery:differential'], matchers=[matchers.prod],
      outputs=['pagerduty:sample-integration'])

You can also supply multiple matchers for many common scenarios:

@rule('root_logins', logs=['osquery:differential'],
      matchers=[matchers.prod, matchers.pci], outputs=['pagerduty:sample-integration'])
"""


class AwsGuardDutyMatcher:
    """A class contains matchers for AWS GuardDuty service"""
    @classmethod
    def guard_duty(cls, rec):
        return rec['detail-type'] == 'GuardDuty Finding'


class StreamQueryMatcher:
    """A class contains matchers for StreamQuery"""
    def streamquery_queury_name(*packs):
        def _matcher(rec):
            return rec.get('execution', {}).get('name', '') in set(packs)

        return _matcher


class OsqueryMatcher:
    """A class defines contains matchers for Osquery events"""

    _EVENT_TYPE_LOGIN = 7
    _RUNLEVELS = {'', 'LOGIN', 'reboot', 'shutdown', 'runlevel'}

    @classmethod
    def added(cls, rec):
        return rec['action'] == 'added'

    @classmethod
    def user_login(cls, rec):
        """Capture user logins from the osquery last table
        This matcher assumes we use default osquery pack shipped with osquery package
        located at /usr/share/osquery/packs/incident-response.conf on the linux host.
        Update the pack name (rec['name']) if it is different.
        """
        return (rec['name'] == 'pack_incident-response_last'
                and int(rec['columns']['type']) == cls._EVENT_TYPE_LOGIN
                and (rec['columns']['username'] not in cls._RUNLEVELS))


class AwsConfigMatcher:
    """Contains Matchers relevant to AWS Config"""
    @staticmethod
    def is_config_compliance(rec):
        """Check if the record event is from config compliance

        Args:
            rec (dict): Parsed log to check key/value pairs

        Returns:
            bool: True if from config and not in testMode else False
        """
        return (rec['eventSource'] == 'config.amazonaws.com'
                and rec['eventName'] == 'PutEvaluations'
                and not rec['requestParameters']['testMode'])

    @staticmethod
    def is_auto_remediation(rec):
        """Check if the record is an auto-remediation event

        Args:
            rec (dict): Parsed log to check key/value pairs
        Returns:
            bool: True if auto_remediation event else False
        """
        return (rec['eventName'] == 'StartAutomationExecution'
                and rec['eventSource'] == 'ssm.amazonaws.com'
                and rec['sourceIPAddress'] == 'config.amazonaws.com')
