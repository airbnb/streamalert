Datasource Configuration
========================

For background on supported datasource types, read `datasources <datasources.html>`_.

Overview
--------

Datasources defined in ``conf/sources.json`` control which datasources can send to and be analyzed by StreamAlert.

Each datasource (``kinesis``, ``s3``, or ``sns``) contains a mapping of specific datasource names (kinesis stream names, s3 bucket IDs) along with a list of logs coming from that source.

Log schemas are defined in ``conf/logs.json``

Each log in the list of ``logs`` dictates to StreamAlert how to parse incoming data from that entity.  Data will only be analyzed if its type is defined here.

Example::

    {
      "kinesis": {                               # define each kinesis stream w/respective logs
        "abc_corporate_stream_alert_kinesis": {  # kinesis stream name
          "logs": [                              #  expected log types
            "box",
            "pan"
          ]
        },
        "abc_production_stream_stream_alert_kinesis": {
          "logs": [
            "inspec",
            "osquery"
          ]
        },
        ...
      },
      "s3": {                      # define each s3 bucket w/respective logs
        "abc.webserver.logs": {    # s3 bucket name
          "logs": [                # expected log types
            "nginx"
          ]
        },
        "abc.hids.logs": {
          "logs": [
            "carbonblack"
          ]
        },
        ...
      },
      "sns": {
        "abc_sns_topic": {
          "logs": [
            "logstash"
          ]
        }
      }
    }

Once datasources are defined, associated ``logs`` must have defined `schemas <conf-schemas.html>`_
