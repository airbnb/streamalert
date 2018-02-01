Getting Started
===============

Perform the following steps on your laptop or development machine

Dependencies
------------

1. Install Python 2.7 and `pip <https://pip.pypa.io/en/stable/installing/>`_
2. Install `Terraform <https://www.terraform.io/intro/getting-started/install.html>`_
3. Download StreamAlert:

.. code-block:: bash

  $ git clone https://github.com/airbnb/streamalert.git
  $ cd streamalert

4. Install and activate Virtualenv:

.. code-block:: bash

  $ pip install virtualenv
  $ virtualenv -p python2.7 venv
  $ source venv/bin/activate

5. Install dependencies:

.. code-block:: bash

  $ pip install -r requirements.txt


.. note:: If you run into issues with ``psutil`` installation, make sure you have the ``python-dev`` dependencies installed.  `debian: sudo apt install python-dev``, `CentOS/RHEL: sudo yum install python-devel``


Quick Start
-----------

1. Define your `AWS account <account.html>`_
2. Define your `clusters <clusters.html>`_
3. Define your `datasources <conf-datasources.html>`_
4. Define your `schemas <conf-schemas.html>`_
5. Configure your `kinesis stream/firehose <kinesis.html>`_
6. Configure your `lambda settings <lambda.html>`_
7. Write your `rules <rules.html>`_
8. Configure your `outputs <outputs.html#configuration>`_

Now it's time to `deploy <deployment.html>`_!
