#!/usr/bin/env python
import sys
import json
from io import BytesIO
import boto3
from botocore.exceptions import ClientError

FILE_NAME = 'ssm_ready_secrets.json'


def decrypt_secrets(ciphertext, region):
    """Decrypts the given ciphertext using AWS KMS

    Args:
        ciphertext (str): The raw, encrypted data to be decrypted
        region (str): AWS region

    Returns:
        string: The decrypted plaintext

    Raises:
        ClientError
    """
    client = boto3.client('kms', region_name=region)
    try:
        response = client.decrypt(CiphertextBlob=ciphertext)
    except ClientError:
        print('An error occurred during KMS decryption')
        raise
    else:
        return response['Plaintext']


def pull_from_s3(bucket, key):
    """Pull file contents from S3 into memory

    Args:
        bucket (boto3.resources.factory.s3.Bucket): The S3 Bucket resource
        key (str): The key to pull

    Returns:
        None: An error occured
        ciphertext: The encrypted contents of the file

    Raises:
        ClientError
    """
    io = BytesIO()

    try:
        bucket.download_fileobj(key, io)
    except ClientError:
        print(f"Error fetching {key} from s3")
        raise
    else:
        return io.getvalue()


def get_output_secrets(bucket, key, region):
    """Pull the secrets from s3

    Args:
        bucket (boto3.resources.factory.s3.Bucket): The S3 Bucket resource
        key (str): The key to download and decrypt
    Returns:
        None: An error occured
        dict: The secrets from s3
    """
    try:
        encrypted_secrets = pull_from_s3(bucket, key)
        secrets = decrypt_secrets(encrypted_secrets, region)
    except ClientError:
        pass
    else:
        return json.loads(secrets)


def save_to_fs(secrets):
    """Save the secrets to the local FileSystem

    Args:
        secrets (dict): Secrets ready to be taken by set-from-file subcommand
    """

    saved = False

    try:
        with open(FILE_NAME, "w") as _fp:
            json.dump(secrets, _fp)
    except Exception:
        print("Error saving secrets to FileSystem")
    else:
        print(f"Secrets saved to {FILE_NAME}")
        saved = True

    return saved


if __name__ == "__main__":
    import os
    sys.path.append(os.path.realpath('.'))

    from streamalert.alert_processor.outputs.output_base import (
        StreamAlertOutput
    )
    from streamalert_cli.config import CLIConfig

    config = CLIConfig()
    output_config = config.get("outputs")
    if not output_config:
        print("No Outputs configured")
        sys.exit(1)

    region = config["global"]["account"]["region"]
    prefix = config["global"]["account"]["prefix"]

    bucket_name = f"{prefix}.streamalert.secrets"
    s3 = boto3.resource('s3', region_name=region)
    bucket = s3.Bucket(bucket_name)

    secrets = {}
    for service, descriptors in output_config.items():
        dispatcher = StreamAlertOutput.get_dispatcher(service)
        required_properties = dispatcher.get_user_defined_properties()

        if not any(prop.cred_requirement for prop in required_properties.values()):
            # The service has no 'cred_requirement' so it will not contain anything in s3
            continue

        service_outputs = []

        for descriptor in descriptors:
            if 'sample' in descriptor:
                # Skip sample outputs
                continue

            key = f"{service}/{descriptor}"
            output_secrets = get_output_secrets(bucket, key, region)
            if not output_secrets:
                print(f"No Secrets Found for {service}:{descriptor}")
                continue

            output_secrets["descriptor"] = descriptor
            service_outputs.append(output_secrets)

        if service_outputs:
            # Add the service secrets into the secrets dict
            secrets[service] = service_outputs

    if not save_to_fs(secrets):
        # An error occured so exit with code 1
        sys.exit(1)

    print(
        "\nPlease Upgrade to the release containing SSM as the secret_store and then run"
        f"\n\n $ python manage.py output set-from-file --file --update {FILE_NAME}\n\nto push",
        "the secrets to SSM"
    )
