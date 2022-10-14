"""Alert on calls made without MFA that may be attempting to abuse a flawed enforcement policy"""
from streamalert.shared.rule import rule

_IAM_ACTIONS = {
    'CreateUser', 'CreateAccessKey', 'DetachUserPolicy', 'DetachGroupPolicy', 'RemoveUserFromGroup',
    'DeleteUserPolicy', 'PutGroupPolicy', 'PutUserPolicy'
}

_EVENT_NAMES = {'CreateVirtualMFADevice', 'EnableMFADevice'}


@rule(logs=['cloudtrail:events'])
def cloudtrail_mfa_policy_abuse_attempt(rec):
    """
    author:           Scott Piper of Summit Route in collaboration with Duo Security
    description:      Alert on potential attacks performed by users that are supposed to have
                        MFA enforced. May indicate leaked access keys and an attempt to abuse
                        a flawed MFA enforcement policy.
    playbook:         (a) Identify whether or not the attempt was a mistake.
                      (b) Begin IR: Roll access keys, investigate past CloudTrail logs for
                      other actions performed, investigate how the keys were leaked in the
                      first place.
    """

    # Depending on the practices you follow with AWS today, you may wish to simply alert
    # on any errors at all in AWS, possibly with some focus on IAM actions,
    # and possibly with some exemptions to ignore things like failed login attempts.
    # Another option would be to just alert on any AccessDenied's when MFA is not used.
    # This rule attempts to reduce the false positives.

    # Get the value for whether the user is MFA authenticated.
    # If this doesn't exist, assume not MFA authenticated.
    try:
        mfa_authenticated = rec['userIdentity']['sessionContext']['attributes']['mfaAuthenticated']
    except KeyError:
        mfa_authenticated = 'false'

    # If the user is MFA authenticated, then any issues are not due to just a compromised
    # access key, so ignore it.
    if mfa_authenticated == 'true':
        return False

    # If the user tries to remove their MFA device without being MFA authenticated,
    # it could be an attacker trying to take advantage of an issue with an older AWS policy.
    if rec['eventName'] == 'DeactivateMFADevice':
        return True

    # Similarly, the attacker could try some other IAM actions under the assumption that the user
    # is an admin with the flawed policy. There are a lot of actions they could try, which should
    # be blocked by your policy anyway now, but these should detect most of the actions an attacker
    # would try.
    if rec['eventName'] in _IAM_ACTIONS:
        return True

    # If the user tries to create or enable an MFA device, but they are unable to, it could mean
    # they are attempting to exploit a race condition where they wait for the user to one day
    # swap MFA devices.
    # This will have an errorCode of:
    # - 'AccessDenied'
    # - 'EntityAlreadyExists': Can't create another MFA device with the same name.
    # - 'LimitExceeded': Can't enable a second MFA device for the same user.
    return bool(rec['errorCode'] and rec['eventName'] in _EVENT_NAMES)
