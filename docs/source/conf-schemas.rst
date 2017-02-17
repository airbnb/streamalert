Schemas
=======

Overview
--------

Schemas are defined in ``conf/logs.json``

**CloudTrail** Example::

  "cloudtrail": {                           # log-type
    "parser": "json",                       # data-type
    "schema": {                             # begin schema definition
      "Records": [
        {
          "eventVersion": "string",         # type checking
          "eventID": "string",
          "eventTime": "string",
          "requestParameters": "string",
          "eventType": "string",
          "responseElements": "string",
          "awsRegion": "string",
          "eventName": "string",
          "userIdentity": "string",
          "eventSource": "string",
          "requestID": "string",
          "apiVersion": "string",
          "userAgent": "string",
          "sourceIPAddress": "string",
          "recipientAccountId": "string"
        }
      ]
    }
  },
  ....


Here are the basics:

* Keys defined in the ``schema`` must exist
* Values are weakly/loosely typed and enforced
* Arrays imply zero or more elements
* An empty hash ({}) implies zero or more elements
* Schemas can be as tight or as loose as you want (see Example: osquery)

JSON Example: Inspec
--------------------
Schema::

  "inspec": {
    "schema": {
      "profiles": [
        {
          "controls": [
            {
              "title": "string",
              "desc": "string",
              "impact": "string",
              "refs": "string",
              "tags": "string",
              "code": "string",
              "id": "string",
              "source_location": "string",
              "results": "string"
            }
          ]
        }
      ]
    },
    "parser": "json"
  },

JSON Example: box.com
---------------------

Schema::

  "box": {
    "schema": {
      "source": "string",
      "created_by": "string",
      "created_at": "string",
      "event_id": "string",
      "event_type": "string",
      "ip_address": "string",
      "type": "string",
      "session_id": "string",
      "additional_details": "string"
    },
    "parser": "json"
  },

JSON Example: osquery
---------------------

osquery's schema depends on the table being queried and there are 50+ tables

**Option 1**: Define a schema for each table used::

  "osquery:etc_hosts": {
    "parser": "json",
    "schema": {
      "name": "string",
      ...
      "columns": {
        "address": "string",
        "hostnames": "string"
      },
      "action": "string",
      ...
    }
  },
  "osquery:listening_ports": {
    "parser": "json",
    "schema": {
      "name": "string",
      ...
      "columns": {
        "pid": "integer",
        "port": "integer",
        "protocol": "integer",
        ...
      },
      "action": "string",
      ...
    }
  },
  ...

This promotes Rule safety, but requires additional time to define the schemas


**Option 2**: Define a "loose" schema that captures all tables::

  "osquery": {
    "parser": "json",
    "schema": {
      "name": "string",
      "hostIdentifier": "string",
      "calendarTime": "string",
      "unixTime": "integer",
      "columns": {},                 # {} = any keys
      "action": "string"
    }
  },

.. warning:: In Option 2, the schema definition is flexible, but Rule safety is lost because you'll need to use defensive programming when accessing and analyzing fields in `columns`. The use of `req_subkeys` will be advised, see Rules for more details

CSV Example
-----------

Example schema::

  "example_csv_log_type": {
    "parser": "csv",          # define the parser as CSV
    "schema": {
      "time": "integer",      # columns are represented as keys; ordering is strict
      "user": "string",
      "message": "string"
    },
    "hints": {                # hints are used to aid in data classification
      "user": [
        "john_adams"          # user must be john_adams
      ],
      "message": [            # message must be "apple*" OR "*orange"
        "apple*",
        "*orange"
      ]
    }
  },

For CSV, ``hints`` are used to aid in data classification since StreamAlert is stateless and does not have access to the CSV header


Example logs::

  1485729127,john_adams,apple            # match: yes (john_adams, apple*)
  1485729127,john_adams,apple tree       # match: yes (john_adams, apple*)
  1485729127,john_adams,fuji apple       # match: no
  1485729127,john_adams,orange           # match: yes (john_adams, *orange)
  1485729127,john_adams,bright orange    # match: yes (john_adams, *orange)
  1485729127,chris_doey,bright orange    # match: no



CSV Example w/nesting
---------------------

Some CSV logs have nested fields

Example logs::

  1485729127,john_adams,memcache us-east1    # time,user,message; message = role,region
  1485729127,john_adams,mysqldb us-west1


You can support this with a schema like the following::

  "example_csv_with_nesting": {
    "parser": "csv",
    "schema": {
      "time": "integer",
      "user": "string",
      "message": {
        "role": "string",
        "region": "string"
      }
    },
    "hints": [
      ...
    ]
  },

Key-Value (KV) Example
----------------------

Example schema::

  "example_auditd": {
    "parser": "kv",          # define the parser as kv
    "delimiter": " ",        # define the delimiter
    "separator": "=",        # define the separator
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
    }
  },

Syslog Example
--------------

Example schema::

  "example_syslog": {
    "parser": "syslog",
    "schema": {
      "timestamp": "string",
      "host": "string",
      "application": "string",
      "message": "string"
    }
  }


StreamAlert is configured to match syslog events with the following format::

  timestamp(Month DD HH:MM:SS) host application: message

Example(s)::

  Jan 10 19:35:33 vagrant-ubuntu-trusty-64 sudo: session opened for root
  Jan 10 19:35:13 vagrant-ubuntu-precise-32 ssh[13941]: login for jack

