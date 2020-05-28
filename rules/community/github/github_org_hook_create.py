"""Github organization-wide hook was created."""
from streamalert.shared.rule import rule


@rule(logs=['ghe:general'])
def github_org_hook_create(rec):
    """
    author:       @mimeframe
    description:  Github organization-wide hook was created.
                  Organization hooks receive events for all repositories in an
                  organization and have the potential to leak a lot of data.
    repro_steps:  (a) Visit /organizations/<org>>/settings/hooks
    """
    return rec['action'] == 'hook.create' and rec['data']['hook_type'] == 'org'

