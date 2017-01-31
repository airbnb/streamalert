Lambda
======

Overview
--------

* StreamAlert utilizes AWS Lambda for data processing and alerting
* AWS Lambda lets us run code without needing to provision or manage servers
* A Lambda function is created for each `cluster <clusters.html>`_ you define.

Concepts
--------
* AWS Lambda `details`_
* AWS Lambda `faq`_
* AWS Lambda `pricing`_

.. _details: https://docs.aws.amazon.com/lambda/latest/dg/welcome.html
.. _faq: https://aws.amazon.com/lambda/faqs/
.. _pricing: https://aws.amazon.com/lambda/pricing/

Fields
------

lambda_settings
~~~~~~~~~~~~~~~

Example::

    "lambda_settings": {
        "corporate": [      # cluster name
            60,             # lambda timeout
            192             # lambda memory
        ],
        "production": [
            10,
            128
        ],
        ...
    },


The ``timeout`` defines how long (seconds) the lambda function is allowed to process an incoming record.

Per documentation: *"All calls made to AWS Lambda must complete execution within 300 seconds. The default timeout is 3 seconds, but you can set the timeout to any value between 1 and 300 seconds."*

lambda_source_bucket_name
~~~~~~~~~~~~~~~~~~~~~~~~~

Example::

    "lambda_source_bucket_name": "companyx.streamalert.source",

This defines the S3 bucket to create/use for uploading and storing the StreamAlert application code

