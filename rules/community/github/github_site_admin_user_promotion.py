"""A Github Enterprise user account was promoted to a site admin."""
from streamalert.shared.rule import rule


@rule(logs=['ghe:general'])
def github_site_admin_user_promotion(rec):
    """
    author:       @fusionrace, @mimeframe
    description:  Alert when a Github Enterprise user account is promoted to a
                  Site Administrator (privileged account)
    reference:    https://help.github.com/enterprise/2.11/admin/guides/
                  user-management/promoting-or-demoting-a-site-administrator/
    """
    return rec['action'] == 'user.promote'
