###############
Example Schemas
###############
For additional background on schemas, see `Schemas <config-schemas.html>`_


****
JSON
****

CloudWatch
==========

Example Log
-----------
.. code-block:: json

  {
    "version": "0",
    "id": "6a7e8feb-b491-4cf7-a9f1-bf3703467718",
    "detail-type": "EC2 Instance State-change Notification",
    "source": "aws.ec2",
    "account": "111122223333",
    "time": "2015-12-22T18:43:48Z",
    "region": "us-east-1",
    "resources": [
      "arn:aws:ec2:us-east-1:123456789012:instance/i-12345678"
    ],
    "detail": {
      "instance-id": "i-12345678",
      "state": "terminated"
    }
  }


Schema
------
.. code-block:: json

  {
    "cloudwatch:ec2_event": {
      "schema": {
        "version": "string",
        "id": "string",
        "detail-type": "string",
        "source": "string",
        "account": "integer",
        "time": "string",
        "region": "string",
        "resources": [],
        "detail": {
          "instance-id": "string",
          "state": "string"
        }
      },
      "parser": "json"
    }
  }


Inspec
======

Example Log
-----------
.. code-block:: json

  {
    "version": "1.4.1",
    "profiles": [
      {
        "supports": [],
        "controls": [
          {
            "title": null,
            "desc": null,
            "impact": 0.5,
            "refs": [],
            "tags": {},
            "code": "code-snip",
            "source_location": {
              "ref": "/lib/inspec/control_eval_context.rb",
              "line": 87
            },
            "id": "(generated from osquery.rb:6 de0aa7d2405c27dfaf34a56e2aa67842)",
            "results": [
              {
                "status": "passed",
                "code_desc": "File /var/osquery/osquery.conf should be file",
                "run_time": 0.001332,
                "start_time": "2017-01-01 00:00:00 -0700"
              }
            ]
          }
        ],
        "groups": [
          {
            "title": null,
            "controls": [
              "(generated from osquery.rb:1 813971f93b6f1a66e85f6541d49bbba5)",
              "(generated from osquery.rb:6 de0aa7d2405c27dfaf34a56e2aa67842)"
            ],
            "id": "osquery.rb"
          }
        ],
        "attributes": []
      }
    ],
    "other_checks": [],
    "statistics": {
      "duration": 0.041876
    }
  }


Schema
------
.. code-block:: json

  {
    "inspec": {
      "schema": {
        "title": "string",
        "desc": "string",
        "impact": "float",
        "refs": [],
        "tags": {},
        "code": "string",
        "id": "string",
        "source_location": {
          "ref": "string",
          "line": "integer"
        },
        "results": []
      },
      "parser": "json",
      "configuration": {
        "json_path": "profiles[*].controls[*]"
      }
    }
  }


Box.com
=======

Example Log
-----------
.. code-block:: json

  {
    "source": {
      "item_type": "file",
      "item_id": "111111111111",
      "item_name": "my-file.pdf",
      "parent": {
        "type": "folder",
        "name": "Files",
        "id": "22222222222"
      }
    },
    "created_by": {
      "type": "user",
      "id": "111111111",
      "name": "User Name",
      "login": "user.name@domain.com"
    },
    "created_at": "2017-01-01T00:00:00-07:00",
    "event_id": "111ccc11-7777-4444-aaaa-dddddddddddddd",
    "event_type": "EDIT",
    "ip_address": "127.0.0.1",
    "type": "event",
    "session_id": null,
    "additional_details": {
      "shared_link_id": "sadfjaksfd981348fkdqwjwelasd9f8",
      "size": 14212335,
      "ekm_id": "111ccc11-7777-4444-aaaa-dddddddddd",
      "version_id": "111111111111",
      "service_id": "5555",
      "service_name": "Box Sync for Mac"
    }
  }


Schema
------
.. code-block:: json

  {
    "box": {
      "schema": {
        "source": {
          "item_type": "string",
          "item_id": "integer",
          "item_name": "string",
          "parent": {
            "type": "string",
            "name": "string",
            "id": "integer"
          }
        },
        "created_by": {
          "type": "string",
          "id": "integer",
          "name": "string",
          "login": "string"
        },
        "created_at": "string",
        "event_id": "string",
        "event_type": "string",
        "ip_address": "string",
        "type": "string",
        "session_id": "string",
        "additional_details": {}
      },
      "parser": "json"
    }
  }


CloudWatch VPC Flow Logs
========================
AWS VPC Flow Logs can be delivered to StreamAlert via CloudWatch.

CloudWatch logs are delivered as a nested record, so we will need to pass ``configuration`` options to the parser to find the nested records:


Schema
------
.. code-block:: json

  {
    "cloudwatch:flow_logs": {
      "schema": {
        "protocol": "integer",
        "source": "string",
        "destination": "string",
        "srcport": "integer",
        "destport": "integer",
        "action": "string",
        "packets": "integer",
        "bytes": "integer",
        "windowstart": "integer",
        "windowend": "integer",
        "version": "integer",
        "eni": "string",
        "account": "integer",
        "flowlogstatus": "string"
      },
      "parser": "json",
      "configuration": {
        "json_path": "logEvents[*].extractedFields",
        "envelope_keys": {
          "logGroup": "string",
          "logStream": "string",
          "owner": "integer"
        }
      }
    }
  }


osquery
=======

Osquery's schema changes depending on the ``SELECT`` statement used and the table queried.  There are several options when writing schemas for these logs.


Schema, Option #1
-----------------
Define a schema for each table used:

.. code-block:: json

  {
    "osquery:etc_hosts": {
      "parser": "json",
      "schema": {
        "name": "string",
        "columns": {
          "address": "string",
          "hostnames": "string"
        },
        "action": "string",
        "field...": "type..."
      }
    },
    "osquery:listening_ports": {
      "parser": "json",
      "schema": {
        "name": "string",
        "columns": {
          "pid": "integer",
          "port": "integer",
          "protocol": "integer",
          "field...": "type..."
        },
        "action": "string",
        "field...": "type..."
      }
    }
  }

This approach promotes Rule safety, but requires additional time to define the schemas.


Schema, Option #2
-----------------
Define a "loose" schema which captures arbitrary values for a given field:

.. code-block:: json

  {
    "osquery:differential": {
      "parser": "json",
      "schema": {
        "name": "string",
        "hostIdentifier": "string",
        "calendarTime": "string",
        "unixTime": "integer",
        "columns": {},
        "action": "string"
      }
    }
  }

.. note:: The value for ``columns`` above of ``{}`` indicates that a map with any key/value pairs is acceptable.

.. warning:: In Option 2, the schema definition is flexible, but Rule safety is lost because you will need to use defensive programming when accessing and analyzing fields in `columns`. The use of `req_subkeys` will be advised in this case, see `Rules <rules.html>`_ for additional details.

***
CSV
***

See `CSV Parsing <config-schemas.html#csv-parsing>`_

**************
Key-Value (KV)
**************

auditd
======

Example Log
-----------
.. code-block::

  type=SYSCALL msg=audit(1364481363.243:24287): arch=c000003e syscall=2 success=no exit=-13
  a0=7fffd19c5592 a1=0 a2=7fffd19c4b50 a3=a items=1 ppid=2686 pid=3538 auid=500 uid=500
  gid=500 euid=500 suid=500 fsuid=500 egid=500 sgid=500 fsgid=500 tty=pts0 ses=1 comm="cat"
  exe="/bin/cat" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="sshd_config"
  type=CWD msg=audit(1364481363.243:24287):  cwd="/home/shadowman" type=PATH msg=audit(1364481363.243:24287):
  item=0 name="/etc/ssh/sshd_config" inode=409248 dev=fd:00 mode=0100600 ouid=0 ogid=0
  rdev=00:00 obj=system_u:object_r:etc_t:s0


Schema
------
.. code-block:: json

  {
    "example_auditd": {
      "parser": "kv",
      "schema": {
        "type": "string",
        "msg": "string",
        "arch": "string",
        "syscall": "string",
        "success": "string",
        "exit": "string",
        "a0": "string",
        "a1": "string",
        "a2": "string",
        "a3": "string",
        "items": "string",
        "ppid": "integer",
        "pid": "integer",
        "auid": "integer",
        "uid": "integer",
        "gid": "integer",
        "euid": "integer",
        "suid": "integer",
        "fsuid": "integer",
        "egid": "integer",
        "sgid": "integer",
        "fsgid": "integer",
        "tty": "string",
        "ses": "string",
        "comm": "string",
        "exe": "string",
        "subj": "string",
        "key": "string",
        "type_2": "string",
        "msg_2": "string",
        "cwd": "string",
        "type_3": "string",
        "msg_3": "string",
        "item": "string",
        "name": "string",
        "inode": "string",
        "dev": "string",
        "mode": "integer",
        "ouid": "integer",
        "ogid": "integer",
        "rdev": "string",
        "obj": "string"
      },
      "configuration": {
        "delimiter": " ",
        "separator": "="
      }
    }
  }

.. note::

  The value for ``parser`` above should be set to ``kv`` for key-value parsing. The ``delimiter`` and
  ``separator`` keys within ``configuration`` indicate the values to use for delimiter and field
  separator, respectively.


******
Syslog
******

See `Syslog Parsing <config-schemas.html#syslog-parsing>`_
