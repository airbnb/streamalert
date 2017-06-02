{
    "terraform": {
        "required_version": "> 0.9.0", 
        "backend": {
            "local": {
                "path": "terraform/terraform.tfstate"
            }
        }
    }, 
    "prodiver": {
        "aws": {}
    }, 
    "resource": {
        "aws_kms_alias": {
            "stream_alert_secrets": {
                "target_key_id": "${aws_kms_key.stream_alert_secrets.key_id}", 
                "name": "alias/stream_alert_secrets"
            }
        }, 
        "aws_s3_bucket": {
            "stream_alert_secrets": {
                "force_destroy": true, 
                "bucket": "PREFIX_GOES_HERE.streamalert.secrets", 
                "versioning": {
                    "enabled": true
                }, 
                "acl": "private"
            }, 
            "lambda_source": {
                "force_destroy": true, 
                "bucket": "PREFIX_GOES_HERE.streamalert.source", 
                "versioning": {
                    "enabled": true
                }, 
                "acl": "private"
            }, 
            "terraform_state": {
                "force_destroy": true, 
                "bucket": "PREFIX_GOES_HERE.streamalert.terraform.state", 
                "versioning": {
                    "enabled": true
                }, 
                "acl": "private"
            }
        }, 
        "aws_kms_key": {
            "stream_alert_secrets": {
                "enable_key_rotation": true, 
                "description": "StreamAlert secret management"
            }
        }
    }
}