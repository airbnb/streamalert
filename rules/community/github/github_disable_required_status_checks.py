"""Github 'required status checks' was disabled for a repo."""
from streamalert.shared.rule import rule


@rule(logs=['ghe:general'])
def github_disable_required_status_checks(rec):
    """
    author:       @mimeframe
    description:  The 'required status checks' feature was disabled for a repository.
                  Settings -> Branches -> Protected Branches -> <choose a branch>
    repro_steps:  (a) Choose a repository
                  (b) Click Settings -> Branches -> Protected Branches -> <branch>
                  (c) Uncheck 'Require status checks to pass before merging'
    reference:    https://help.github.com/articles/enabling-required-status-checks/
    """
    return (
        rec['action'] == 'protected_branch.update_required_status_checks_enforcement_level' and
        # 0 => unchecked
        # 1 => enabled for users
        # 2 => enabled for users and admins ('Include administrators')
        rec['data'].get('required_status_checks_enforcement_level') == 0)
