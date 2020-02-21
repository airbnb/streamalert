"""A Github site admin tool/action was used."""
from streamalert.shared.rule import rule


@rule(logs=['ghe:general'])
def github_site_admin_action(rec):
    """
    author:       @mimeframe
    description:  A Github site admin tool/action was used.
                  Example: 'staff.fake_login'
                   "A site admin signed into GitHub Enterprise as another user.""
    reference:    https://help.github.com/enterprise/2.11/admin/articles/audited-actions/
    """
    return rec['action'].startswith('staff.')
