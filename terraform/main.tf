{
    "prodiver": {
        "aws": {}
    }, 
    "resource": {
        "aws_kms_alias": {
            "stream_alert_secrets": {
                "name": "alias/stream_alert_secrets", 
                "target_key_id": "${aws_kms_key.stream_alert_secrets.key_id}"
            }
        }, 
        "aws_kms_key": {
            "stream_alert_secrets": {
                "description": "StreamAlert secret management", 
                "enable_key_rotation": true
            }
        }, 
        "aws_s3_bucket": {
            "lambda_source": {
                "acl": "private", 
                "bucket": "PREFIX_GOES_HERE.streamalert.source", 
                "force_destroy": true, 
                "versioning": {
                    "enabled": true
                }
            }, 
            "stream_alert_secrets": {
                "acl": "private", 
                "bucket": "PREFIX_GOES_HERE.streamalert.secrets", 
                "force_destroy": true, 
                "versioning": {
                    "enabled": true
                }
            }, 
            "terraform_state": {
                "acl": "private", 
                "bucket": "PREFIX_GOES_HERE.streamalert.terraform.state", 
                "force_destroy": true, 
                "versioning": {
                    "enabled": true
                }
            }
        }
    }, 
    "terraform": {
        "backend": {
            "s3": {
                "acl": "private", 
                "bucket": "PREFIX_GOES_HERE.streamalert.terraform.state", 
                "encrypt": true, 
                "key": "stream_alert_state/terraform.tfstate", 
                "kms_key_id": "alias/stream_alert_secrets", 
                "region": "us-east-1"
            }
        }, 
        "required_version": "> 0.9.0"
    }
}