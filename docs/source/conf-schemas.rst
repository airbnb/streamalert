Schemas
=======

Overview
--------

Log schemas are required by StreamAlert to detect the correct log type of an incoming record.

Schemas are defined in ``conf/logs.json`` and used by rules to determine which records are analyzed.

They represent the structure of a given log in the form of key/value pairs.

Each key in a schema corresponds to the name of a field referenced by rules.  Its value is the data type the field is cast to.

Ordering is strict for the ``csv`` parser.

Example log schema::

  {
    "example_log_name": {
      "parser": "parser-name-goes-here",
      "schema": {
        "field_1": "string",
        "field_2": "integer",
        "field_3": "boolean",
        "field_4": "float",
        "field_5": [],
        "field_6": {}
      }
    }
  }

Example rule:

.. code-block:: python

  @rule(logs=['example_log_name'],              # the log_name as defined above
        matchers=[],
        outputs=['slack'])
  def example_rule(rec):
    """Description of the rule"""
    return (
      rec['field_1'] == 'string-value' and      # fields as defined in the schema above
      rec['field_2'] < 5 and
      'random-key-name' in rec['field_6']
    )


Options
-------

=================  =========  ======================
Key                Required   Description
-----------------  ---------  ----------------------
``parser``         ``true``   The name of the parser to use for a given log's data-type.   Options include ``json, json-gzip, csv, kv, or syslog``
``schema``         ``true``   A map of key/value pairs of the name of each field with its type
``configuration``  ``false``  Configuration options specific to this log type (see table below for more information)
=================  =========  ======================

Optional ``configuration`` Options
----------------------------------

===========================  ======================
Key                          Description
---------------------------  ----------------------
``optional_top_level_keys``  Keys that may or may not be present in a log being parsed
``json_path``                Path to nested records to be 'extracted' from within a JSON object
``envelope_keys``            Used with nested records to identify keys that are at a higher level than the nested records, but still hold some value and should be stored
``log_patterns``             Various patterns to enforce within a log given provided fields
``delimiter``                For use with key/value or csv logs to identify the delimiter character for the log
``separator``                For use with key/value logs to identify the separator character for the log
===========================  ======================


Writing Schemas
---------------
Schema values are strongly typed and enforced.

Normal types:

* ``string`` - ``'example'``
* ``integer`` - ``0``
* ``float`` - ``0.0``
* ``boolean`` - ``true/false``

Special types:

* ``{}`` - zero or more key/value pairs of any type
* ``[]`` - zero or more elements of any type

Casting Normal Types
~~~~~~~~~~~~~~~~~~~~

Example Schema:

.. code-block:: json

  {
    "example_log_name": {
      "parser": "json",
      "schema": {
        "field_1": "string",
        "field_2": "integer",
        "field_3": "boolean"
      }
    }
  }

Example Log Before Parse::

  '{"field_1": "test-string", "field_2": "100", "field_3": "true"}'

Example Log After Parsing:

.. code-block:: python

  {
    'field_1': 'test-string',
    'field_2': 100,
    'field_3': True
  }

Example Rule with Casted Types:

.. code-block:: python

  @rule(logs=['example_log_name'],
        outputs=['example_output'])
  def example_rule(rec):
    return (
      field_2 == 100 and
      field_3 is not False
    )

Casting Special Types
~~~~~~~~~~~~~~~~~~~~~

Schemas can be as rigid or permissive as you want (see Example: osquery).

Usage of the special types normally indicates a loose schema, in that not every part of the incoming data is described.

Example Schema:

.. code-block:: json

  {
    "example_log_name": {
      "parser": "json",
      "schema": {
        "field_1": "string",
        "field_2": "integer",
        "field_3": {}
      }
    }
  }

Example Log Before Parse::

  '{"field_1": "test-string", "field_2": "100", "field_3": {"data": "misc-data", "time": "1491584265"}}'

Example Log After Parsing:

.. code-block:: python

  {
    'field_1': 'test-string',
    'field_2': 100,
    'field_3': {
      'data': 'misc-data',
      'time': '1491584265'
    }
  }

Note the values of ``field_3`` are strings, since no type(s) can be defined with ``{}``.

Example Rule with a loose Schema:

.. code-block:: python

  @rule(logs=['example_log_name'],
        outputs=['example_output'],
        req_subkeys={'field_3': ['time']})
  def example_rule_2(rec):
    return (
      field_2 == 100 and
      last_hour(int(rec['field_3']['time']))
    )

Also note the usage of ``req_subkeys``.

This keyword argument ensures that the parsed log contains the required subkeys of ``rec['field_3']['time']``.

Optional Top Level Keys
~~~~~~~~~~~~~~~~~~~~~~~

If incoming logs occasionally include/exclude certain fields, this can be expressed in the ``configuration`` settings as ``optional_top_level_keys``.

The value of ``optional_top_level_keys`` should be an array, with entries corresponding to the actual key in the schema that is optional. Any keys specified in this array should also be included in the defined schema.

If any of the ``optional_top_level_keys`` do not exist in the log being parsed, defaults are appended to the parsed log depending on the declared value.

Example Schema:

.. code-block: json
  {
    "test_log_type_json": {
      "parser": "json",
      "schema": {
        "key1": [],
        "key2": "string",
        "key3": "integer"
        "key4": "boolean",
        "key5": "string"
      },
      "configuration": {
        "optional_top_level_keys": [
          "key4",
          "key5"
        ]
      }
    }
  }

Example Logs Before Parse::

  '{"key1": [1, 2, 3], "key2": "test", "key3": 100}'
  '{"key1": [3, 4, 5], "key2": "test", "key3": 200, "key4": true}'

Example Logs After Parsing:

.. code-block:: python

  [
    {
      'key1': [1, 2, 3],
      'key2': 'test',
      'key3': 100,
      'key4': False,          # default value for boolean
      'key5': ''              # default value for string
    },
    {
      'key1': [3, 4, 5],
      'key2': 'test',
      'key3': 200,
      'key4': True,           # default is overridden by parsed log
      'key5': ''              # default value for string
    }
  ]


JSON Parsing
------------

Options
~~~~~~~

.. code-block:: json

  {
    "log_name": {
      "parser": "json",
      "schema": {
        "field": "type",
        "field...": "type..."
      },
      "configuration": {
        "json_path": "jsonpath expression",
        "envelope_keys": {
          "field": "type",
          "field...": "type..."
        }
      }
    }
  }

.. note:: Options related to nested JSON are defined within ``configuration``. The ``json_path`` key should hold the JSON path to the records, while ``envelope_keys`` is utilized to capture keys in the root of our nested structure.

Nested JSON
~~~~~~~~~~~

Normally, a log contains all fields to be parsed at the top level:

.. code-block:: json

  {
    "example": 1,
    "host": "myhostname.domain.com",
    "time": "10:00 AM"
  }

In some cases, the fields to be parsed and analyzed may be nested several layers into the data:

.. code-block:: json

  {
    "logs": {
      "results": [
        {
          "example": 1,
          "host": "jumphost-1.domain.com",
          "time": "11:00 PM"
        },
        {
          "example": 2,
          "host": "jumphost-2.domain.com",
          "time": "12:00 AM"
        }
      ]
    },
    "id": 1431948983198,
    "application": "my-app"
  }

To extract these nested records, use the ``configuration`` option ``json_path``:

.. code-block:: json

  {
    "log_name": {
      "parser": "json",
      "schema": {
        "example": "integer",
        "host": "string",
        "time": "string"
      },
      "configuration": {
        "json_path": "logs.results[*]"
      }
    }
  }

Log Patterns
~~~~~~~~~~~~

Log patterns provide the ability to differentiate log schemas that are identical or very close in nature.

They can be added by using the ``configuration`` option ``log_patterns``.

Log patterns are a collection of key/value pairs where the key is the name of the field, and the value is a list of
expressions the log parser will search for in said field of the log. If *any* of the log patterns listed exists in
a specific field, the parser will consider the data valid.

This feature is especially helpful to reduce false positives, since it provides to ability to only match a schema if
specific values are present in a log.

Wild card log patterns are supported using the ``*`` or ``?`` symbols, as shown below.

Example schema:

.. code-block:: json

  {
    "log_name": {
      "schema": {
        "computer_name": "string",
        "hostname": "string",
        "instance_id": "string",
        "process_id": "string",
        "message": "string",
        "timestamp": "float",
        "type": "string"
      },
      "parser": "json",
      "configuration": {
        "log_patterns": {
          "type": [
            "*bad.log.type*"
          ]
        }
      }
    }
  }

Example logs:

.. code-block:: json

  {
    "computer_name": "test-server-name",
    "hostname": "okay_host",
    "instance_id": "95909",
    "process_id": "82571",
    "message": "this is not important info",
    "timestamp": "1427381694.88",
    "type": "good.log.type.value"
  }
.. note:: The above schema will **not** match the configuration above.

.. code-block:: json

  {
    "computer_name": "fake-server-name",
    "hostname": "bad_host",
    "instance_id": "589891",
    "process_id": "72491",
    "message": "this is super important info",
    "timestamp": "1486943917.12",
    "type": "bad.log.type.value"
  }
.. note:: The above schema **will** match the configuration above.

Envelope Keys
~~~~~~~~~~~~~

Continuing with the above example, if the ``id`` and ``application`` keys in the root of the log are needed for analysis, they can be added by using the ``configuration`` option ``envelope_keys``:

.. code-block:: json

  {
    "log_name": {
      "parser": "json",
      "schema": {
        "example": "integer",
        "host": "string",
        "time": "string"
      },
      "configuration": {
        "json_path": "logs.results[*]",
        "envelope_keys": {
          "id": "integer",
          "application": "string"
        }
      }
    }
  }

The resultant parsed records:

.. code-block:: json

  [
    {
      "example": 1,
      "host": "jumphost-1.domain.com",
      "time": "11:00 PM",
      "streamalert:envelope_keys": {
        "id": 1431948983198,
        "application": "my-app"
      }
    },
    {
      "example": 2,
      "host": "jumphost-2.domain.com",
      "time": "12:00 AM",
      "streamalert:envelope_keys": {
        "id": 1431948983198,
        "application": "my-app"
      }
    }
  ]

Gzip JSON
~~~~~~~~~

If incoming records are gzip compressed, use the same options as above but with the ``json-gzip`` parser.

CSV Parsing
-----------

Options
~~~~~~~

.. code-block:: json

  {
    "csv_log_name": {
      "parser": "csv",
      "schema": {
        "field": "type",
        "field...": "type..."
      },
      "configuration": {
        "delimiter": ","
      }
    }
  }

.. note:: A custom delimiter is specified within ``configuration`` above.

By default, the ``csv`` parser will use ``,`` as the delimiter.

The ``configuration`` setting is optional.

Ordering of the fields within ``schema`` is strict.

Nested CSV
~~~~~~~~~~

Some CSV logs have nested fields.

Example logs::

  "1485729127","john_adams","memcache,us-east1"
  "1485729127","john_adams","mysqldb,us-west1"


You can support this with a schema similar to the following:

.. code-block:: json

  {
    "example_csv_with_nesting": {
      "parser": "csv",
      "schema": {
        "time": "integer",
        "user": "string",
        "message": {
          "role": "string",
          "region": "string"
        }
      }
    }
  }

KV Parsing
----------

Options
~~~~~~~

.. code-block:: json

  {
    "kv_log_name": {
      "parser": "kv",
      "schema": {
        "field": "type",
        "field...": "type..."
      },
      "configuration": {
        "delimiter": " ",
        "separator": "="
      }
    }
  }

.. note:: The ``delimiter`` and ``separator`` keys within ``configuration`` indicate the values to use for delimiter and field separator, respectively.

By default, the ``kv`` parser will use a single space as the delimiter and ``=`` as the field separator.

The ``configuration`` setting is optional.

Example schema:

.. code-block:: json

  {
    "example_kv_log_type": {
      "parser": "kv",
      "schema": {
        "time": "integer",
        "user": "string",
        "result": "string"
      }
    }
  }

Example log::

  "time=1039395819 user=bob result=pass"

Syslog Parsing
--------------

Options
~~~~~~~

.. code-block:: json

  {
    "syslog_log_name": {
      "parser": "syslog",
      "schema": {
        "timestamp": "string",
        "host": "string",
        "application": "string",
        "message": "string"
      }
    }
  }

The ``syslog`` parser has no ``configuration`` options.

The schema is also static for this parser because of the regex used to parse records.

Log Format
~~~~~~~~~~

The ``syslog`` parser matches events with the following format::

  timestamp(Month DD HH:MM:SS) host application: message

Example logs::

  Jan 10 19:35:33 vagrant-ubuntu-trusty-64 sudo: session opened for root
  Jan 10 19:35:13 vagrant-ubuntu-precise-32 ssh[13941]: login for user

More Examples
-------------

For a list of schema examples, see `Schema Examples <conf-schemas-examples.html>`_