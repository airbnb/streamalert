Clusters
========

**Background**

StreamAlert will deploy separate infrastructure for each ``cluster`` (environment) you define.

What constitutes a ``cluster`` is up to you.

Example: You could define ``IT``, ``PCI`` and ``Production`` clusters.

**Strategy**

Cluster definition is up to you.

Common patterns:

1. Define a single cluster to receive and process data from all of your environments
2. Define a cluster for each of your environments
3. Define a cluster for each organization, which may have one or more environments

Which one you choose is largely dependent on your processes, requirements and how your team organizes itself

Option \(2\) is encouraged because it provides segmentation for ingestion, analysis and storage, on a per-cluster basis, ensuring that folks only have access to the infrastructure and data they need to get their job done.

**Configuration**

Open ``variables.json`` and define the ``clusters`` field.  Each key is the name of a cluster, with its value being which AWS region you want to create it in.

Example::

    "clusters": {
        "corp_laptops": "us-east-1",
        "corp_servers": "us-east-2",
        "pci": "us-east-1",
        "production": "us-west-2"
    },

Template::

    {
      "id": "cluster-name",
      "region": "region-name",
      "modules": {
        "stream_alert": {
          "alert_processor": {
            "timeout": 25,
            "memory": 128,
            "current_version": "$LATEST",
            # Optional VPC configuration
            "vpc_config": {
              "subnet_ids": [],
              "security_group_ids": []
            },
            # Required for custom S3 buckets and Lambda functions as outputs
            "outputs": {
              "aws-s3": [],
              "aws-lambda": []
            }
          },
          "rule_processor": {
            "timeout": 10,
            "memory": 256,
            "current_version": "$LATEST",
            # Required if custom SNS inputs as configured
            "inputs": {
              "aws-sns:": []
            }
          }
        },
        "cloudwatch_monitoring": {
          "enabled": true
        },
        "kinesis": {
          "streams": {
            "shards": 1,
            "retention": 24
          },
          "firehose": {
            "enabled": true,
            "s3_bucket_suffix": "streamalert.results"
          }
        },
        "kinesis_events": {
          "enabled": true
        },
        # Optional - Configure CloudTrail into Kinesis
        "cloudtrail": {
          "enabled": true,
          "event_pattern": {
            "source": [],
            "detail-type": [],
            "detail": {}
          }
        },
        # Optional - Configure VPC Flow Logs into Kinesis
        "flow_logs": {
          "enabled": true,
          "vpcs": [],
          "subnets": [],
          "enis": []
        }
      },
      # Optional Terraform Outputs
      "outputs": {
        "kinesis": [
          "username",
          "access_key_id",
          "secret_key"
        ]
      }
    }
