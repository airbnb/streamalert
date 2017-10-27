"""Github 'Require pull request reviews before merging' was disabled for a repo."""
from helpers.base import in_set
from stream_alert.rule_processor.rules_engine import StreamRules

rule = StreamRules.rule

@rule(logs=['ghe:general'],
      outputs=['aws-s3:sample-bucket',
               'pagerduty:sample-integration',
               'slack:sample-channel'])
def github_disable_required_pull_request_reviews(rec):
    """
    author:       @mimeframe
    description:  Setting 'Require pull request reviews before merging' was disabled.
                  When enabled, all commits must be made to a non-protected branch
                  and submitted via a pull request with at least one approved review
                  and no changes requested before it can be merged into master.
    repro_steps:  (a) Visit /<org>/<repo>/settings/branches/<branch>
                  (b) Uncheck 'Require pull request reviews before merging'
                  (c) Click 'Save Changes'
    reference:    https://help.github.com/articles/enabling-required-reviews-for-pull-requests/
    """
    actor_ignorelist = {
    }
    return (
        rec['action'] == 'protected_branch.dismissal_restricted_users_teams' and
        rec['data'].get('authorized_actors_only') is True and
        not in_set(rec['actor'], actor_ignorelist)
    )
