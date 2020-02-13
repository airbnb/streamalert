"""
Matchers extract common logic into helpers that can be referenced in
multiple rules.  For example, if we write an osquery rule that
is specific for the `prod` environment, we can define a matcher
and add it to our rules' `matchers` keyword argument:

from rules.matchers import matchers

@rule('root_logins', logs=['osquery:differential'], matchers=[matchers.prod],
      outputs=['pagerduty:sample-integration'])

You can also supply multiple matchers for many common scenarios:

@rule('root_logins', logs=['osquery:differential'],
      matchers=[matchers.prod, matchers.pci], outputs=['pagerduty:sample-integration'])
"""
class GuardDutyMatcher:
    """A class contains matchers for AWS GuardDuty service"""

    @classmethod
    def guard_duty(cls, rec):
        return rec['detail-type'] == 'GuardDuty Finding'

class OsqueryMatcher:
    """A class defines contains matchers for Osquery events"""

    _EVENT_TYPE_LOGIN = 7
    _RUNLEVELS = {
        '',
        'LOGIN',
        'reboot',
        'shutdown',
        'runlevel'
    }


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
        return (
            rec['name'] == 'pack_incident-response_last' and
            int(rec['columns']['type']) == cls._EVENT_TYPE_LOGIN and
            (rec['columns']['username'] not in cls._RUNLEVELS)
        )
