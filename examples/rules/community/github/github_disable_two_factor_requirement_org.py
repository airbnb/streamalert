"""Github two-factor authentication requirement was disabled for an org."""
from streamalert.shared.rule import rule


@rule(logs=['ghe:general'])
def github_disable_two_factor_requirement_org(rec):
    """
    author:       @mimeframe
    description:  Two-factor authentication requirement was disabled for an org.
    repro_steps:  (a) Visit /organizations/<org>/settings/security
                  (b) Uncheck 'Require two-factor authentication...'
                  (c) Click 'Save'
    reference:    https://help.github.com/
                  articles/requiring-two-factor-authentication-in-your-organization/
    """
    return rec['action'] == 'org.disable_two_factor_requirement'
