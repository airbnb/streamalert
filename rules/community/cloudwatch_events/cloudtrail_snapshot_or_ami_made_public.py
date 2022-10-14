"""Alert on resources made public"""
from streamalert.shared.rule import rule


@rule(logs=['cloudtrail:events'])
def cloudtrail_snapshot_or_ami_made_public(rec):
    """
    author:           spiper
    description:      Alert on AWS API calls that make EBS snapshots,
                        RDS snapshots, or AMIs public.
    playbook:         (a) identify the AWS account in the log
                      (b) identify what resource(s) are impacted by the API call
                      (c) determine if the intent is valid, malicious or accidental
    """

    # For each resouce walk through through the request parameters to check
    # if this is adding permissions for 'all'

    # Check AMIs
    if rec['eventName'] == 'ModifyImageAttribute':
        # For AMIs
        params = rec.get('requestParameters', {})
        if params.get('attributeType', '') == 'launchPermission' and 'add' in params.get('launchPermission', {}):
            items = params['launchPermission']['add'].get('items', [])
            for item in items:
                if item.get('group', '') == 'all':
                    return True

    # Check EBS snapshots
    if rec['eventName'] == 'ModifySnapshotAttribute':
        params = rec.get('requestParameters', {})
        if params.get('attributeType', '') == 'CREATE_VOLUME_PERMISSION' and 'add' in params.get('createVolumePermission', {}):
            items = params['createVolumePermission']['add'].get('items', [])
            for item in items:
                if item.get('group', '') == 'all':
                    return True

    # Check RDS snapshots
    if rec['eventName'] == 'ModifyDBClusterSnapshotAttribute':
        params = rec.get('requestParameters', {})
        if 'all' in params.get('valuesToAdd', []):
            return True

    return False
