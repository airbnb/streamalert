"""Alert on insecure Amazon Machine Images (AMIs)."""
from streamalert.shared.rule import rule


@rule(logs=['cloudwatch:events'], req_subkeys={'detail': ['requestParameters', 'eventName']})
def unencrypted_ami_volume(rec):
    """
    author:       airbnb_csirt
    description:  Identifies creation of an AMI with a non encrypted volume
    reference:    https://amzn.to/2rQilUn
    playbook:     (a) Reach out to the user who created the volume
                  (b) Re-create the AMI with encryption enabled
                  (c) Delete the old AMI
    """
    if rec['detail']['eventName'] != 'CreateImage':
        # check the event type early to avoid unnecessary performance impact
        return False

    if rec['detail']['requestParameters'] is None:
        # requestParameters can be defined with a value of null
        return False

    req_params = rec['detail']['requestParameters']
    block_device_items = req_params.get('blockDeviceMapping', {}).get('items', [])
    if not block_device_items:
        return False

    volume_encryption_enabled = {block_device.get('ebs', {}).get('encrypted') for block_device in block_device_items}

    return not any(volume_encryption_enabled)


@rule(logs=['cloudwatch:events'], req_subkeys={'detail': ['requestParameters', 'eventName']})
def public_ami(rec):
    """
    author:       airbnb_csirt
    description:  Identifies creation of an AMI with a non encrypted volume
    reference:    https://amzn.to/2rQilUn
    playbook:     (a) Reach out to the user who created the volume
                  (b) Set the AMI to private
    """
    if rec['detail']['eventName'] != 'ModifyImageAttribute':
        # check the event type early to avoid unnecessary performance impact
        return False

    if rec['detail']['requestParameters'] is None:
        # requestParameters can be defined with a value of null
        return False

    req_params = rec['detail']['requestParameters']
    permission_items = req_params.get('launchPermission', {}).get('add', {}).get('items', [])
    return any(item['group'] == 'all' for item in permission_items)
