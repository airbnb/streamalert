"""Alert when resources are made public."""
import json

from policyuniverse.policy import Policy

from streamalert.shared.rule import rule


@rule(logs=['cloudtrail:events'])
def cloudtrail_public_resources(rec):
    """
    author:           spiper
    description:      Detect resources being made public.

    playbook:         (a) identify the AWS account in the log
                      (b) identify what resource(s) are impacted by the API call
                      (c) determine if the intent is valid, malicious or accidental
    """
    # Check S3
    if rec['eventName'] == 'PutBucketPolicy':
        # S3 doesn't use a policy string, but actual json, unlike all
        # other commands
        policy = rec.get('requestParameters', {}).get('bucketPolicy', None)
        if not policy:
            return False
        policy = Policy(policy)
        if policy.is_internet_accessible():
            return True

    # Get the policy string for each resource
    policy_string = ''

    # Check ElasticSearch
    if rec['eventName'] == 'CreateElasticsearchDomain':
        policy_string = rec.get('requestParameters', {}).get('accessPolicies', '')
    elif rec['eventName'] == 'UpdateElasticsearchDomainConfig':
        policy_string = rec.get('requestParameters', {}).get('accessPolicies', '')

    # Check Glacier Vaults
    elif rec['eventName'] == 'SetVaultAccessPolicy':
        policy_string = (rec.get('requestParameters', {}).get('policy', {}).get('policy', ''))

    # Check SQS
    elif rec['eventName'] == 'SetQueueAttributes':
        policy_string = (rec.get('requestParameters', {}).get('attributes', {}).get('Policy', ''))

    # Check SNS
    elif rec['eventName'] == 'SetTopicAttributes':
        if rec.get('requestParameters', {}).get('attributeName', '') == 'Policy':
            policy_string = rec['requestParameters'].get('attributeValue', '')
    elif rec['eventName'] == 'CreateTopic':
        policy_string = (rec.get('requestParameters', {}).get('attributes', {}).get('Policy', ''))

    # Check ECR
    elif rec['eventName'] == 'SetRepositoryPolicy':
        policy_string = rec.get('requestParameters', {}).get('policyText', '')

    # Check KMS
    elif rec['eventName'] == 'PutKeyPolicy':
        policy_string = rec.get('requestParameters', {}).get('policy', '')
    elif rec['eventName'] == 'CreateKey':
        policy_string = rec.get('requestParameters', {}).get('policy', '')

    # Check SecretsManager
    elif rec['eventName'] == 'PutResourcePolicy':
        policy_string = rec.get('requestParameters', {}).get('resourcePolicy', '')

    # Check the policy
    if policy_string:
        policy = json.loads(policy_string)
        policy = Policy(policy)
        if policy.is_internet_accessible():
            return True

    return False
