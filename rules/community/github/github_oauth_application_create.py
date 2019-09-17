"""An OAuth application was registered within Github."""
from streamalert.shared.rule import rule


@rule(logs=['ghe:general'])
def github_oauth_application_create(rec):
    """
    author:       @mimeframe
    description:  An OAuth application was registered within Github.
    reference:    https://developer.github.com
                  /apps/building-integrations/setting-up-and-registering-oauth-apps/
    """
    return rec['action'] == 'oauth_application.create'
