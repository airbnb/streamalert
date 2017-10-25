"""Github 'required status checks' was disabled for a repo."""
from stream_alert.rule_processor.rules_engine import StreamRules

rule = StreamRules.rule

@rule(logs=['ghe:general'],
      outputs=['aws-s3:sample-bucket',
               'pagerduty:sample-integration',
               'slack:sample-channel'])
def github_disable_required_status_checks(rec):
    """
    author:       @mimeframe
    description:  The 'required status checks' feature was disabled for a repository.
                  Settings -> Branches -> Protected Branches -> <choose a branch>
    reference:    https://help.github.com/articles/enabling-required-status-checks/
    """
    return (
        rec['action'] == 'protected_branch.update_required_status_checks_enforcement_level' and
        rec['data'].get('required_status_checks_enforcement_level') == 0
    )
