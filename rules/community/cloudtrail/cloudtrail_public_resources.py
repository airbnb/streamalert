"""Alert when resources are made public."""
import json
from policyuniverse.policy import Policy
from stream_alert.shared.rule import rule

@rule(logs=['cloudtrail:events'])
def cloudtrail_public_resources(rec):
    """
    author:           spiper
    description:      Detect resources being made public.

    playbook:         (a) identify the AWS account in the log
                      (b) identify what resource(s) are impacted by the API call
                      (c) determine if the intent is valid, malicious or accidental
    """
    # Get the policy string for each resource
    policy_string = ''

    # Check S3
    if rec['eventName'] == 'PutBucketPolicy':
        # S3 doesn't use a policy string, but actual json, unlike all
        # other commands
        policy = rec.get('requestParameters', {}).get('bucketPolicy', None)
        if policy is None:
            return False
        policy = Policy(policy)
        if policy.is_internet_accessible():
            return True

    # Check ElasticSearch
    if rec['eventName'] == 'CreateElasticsearchDomain':
        policy_string = rec.get('requestParameters', {}).get('accessPolicies', '')
    if rec['eventName'] == 'UpdateElasticsearchDomainConfig':
        policy_string = rec.get('requestParameters', {}).get('accessPolicies', '')

    # Check Glacier Vaults
    if rec['eventName'] == 'SetVaultAccessPolicy':
        policy_string = (
            rec.get('requestParameters', {}).get('policy', {}).get('policy', '')
        )

    # Check SQS
    if rec['eventName'] == 'SetQueueAttributes':
        policy_string = (
            rec.get('requestParameters', {}).get('attributes', {}).get('Policy', '')
        )

    # Check SNS
    if rec['eventName'] == 'SetTopicAttributes':
        if rec.get('requestParameters', {}).get('attributeName', '') == 'Policy':
            policy_string = rec['requestParameters'].get('attributeValue', '')
    if rec['eventName'] == 'CreateTopic':
        policy_string = (
            rec.get('requestParameters', {}).get('attributes', '').get('Policy', '')
        )

    # Check ECR
    if rec['eventName'] == 'SetRepositoryPolicy':
        policy_string = rec.get('requestParameters', {}).get('policyText', '')

    # Check KMS
    if rec['eventName'] == 'PutKeyPolicy':
        policy_string = rec.get('requestParameters', {}).get('policy', '')
    if rec['eventName'] == 'CreateKey':
        policy_string = rec.get('requestParameters', {}).get('policy', '')

    # Check SecretsManager
    if rec['eventName'] == 'PutResourcePolicy':
        policy_string = rec.get('requestParameters', {}).get('resourcePolicy', '')

    # Check the policy
    if policy_string != '':
        policy = json.loads(policy_string)
        policy = Policy(policy)
        if policy.is_internet_accessible():
            return True

    return False
