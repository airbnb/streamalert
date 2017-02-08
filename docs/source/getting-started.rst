Getting Started
===============

Perform the following steps on your laptop or development machine

Dependencies
------------

1. Install Python 2.7 and  `pip <https://pip.pypa.io/en/stable/installing/>`_
2. Install `Terraform <https://www.terraform.io/intro/getting-started/install.html>`_
3. Download StreamAlert: ``git clone https://github.com/airbnb/streamalert.git``
4. Install dependencies: ``pip install -r requirements.txt``

.. note:: For Mac OSX/Homebrew users, add the following to ~/.pydistutils.cfg:

.. code-block:: python

   [install]
   prefix=

Quick Start
-----------

1. Define your `AWS account <account.html>`_
2. Define your `clusters <clusters.html>`_
3. Define your `datasources <conf-datasources.html>`_
4. Define your `schemas <conf-schemas.html>`_
5. Configure your `kinesis streams <kinesis-streams.html>`_
6. Configure your `kinesis firehose <kinesis-firehose.html>`_
7. Configure your `lambda settings <lambda.html>`_
8. Write your `rules <rules.html>`_
9. Define/deploy your `secrets <secrets.html>`_

Now it's time to `deploy <deployment.html>`_!
