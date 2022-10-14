"""Detect ssh login activity based on osquery last table"""
from matchers.default import OsqueryMatcher
from streamalert.shared.rule import rule


@rule(logs=['osquery:differential'], matchers=[OsqueryMatcher.added, OsqueryMatcher.user_login])
def ssh_login_activity(_):
    """
    author:           chunyong-lin
    description:      Detect on ssh login activity to the linux host based on osquery
                      last table. This rule assumes we use default osquery pack
                      shipped with osquery package located at
                      /usr/share/osquery/packs/incident-response.conf on the linux
                      host. Update the pack name in rules/matchers/matchers.py if different.
    reference:        https://osquery.io/schema/4.1.2#last
    """
    return True
