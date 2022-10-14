"""Alert when root AWS credentials are used."""
from streamalert.shared.rule import rule


@rule(logs=['cloudwatch:events'], req_subkeys={'detail': ['userIdentity', 'eventType']})
def cloudtrail_root_account_usage(rec):
    """
    author:           airbnb_csirt
    description:      Root AWS credentials are being used;
                      This is against best practice and may be an attacker
    reference_1:      https://aws.amazon.com/premiumsupport/knowledge-center/
                          cloudtrail-root-action-logs/
    reference_2:      http://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html
    playbook:         (a) identify who is using the Root account
                      (b) ping the individual to determine if intentional and/or legitimate
    """
    # reference_1 contains details on logic below
    return (rec['detail']['userIdentity']['type'] == 'Root'
            and rec['detail']['userIdentity'].get('invokedBy') is None
            and rec['detail']['eventType'] != 'AwsServiceEvent')
