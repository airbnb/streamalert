How to set up the aliyun app
###########################

The Aliyun API requires an access key and access key secret for an authorized user.

To obtain the access key and access key secret, an authorized user of the Aliyun account should follow their directions to `Create an Access Key <https://www.alibabacloud.com/help/doc-detail/53045.htm>`_.

Additionly, the user for whom the access key was created must have sufficient privileges to make use of ActionTrail; follow the directions on the `Grant ActionTrail permissions to RAM users <https://www.alibabacloud.com/help/doc-detail/28818.htm>`_ page.

How to set up the intercom app
##############################

The Intercom API requires an access token. Get an access token by following `these instructions <https://developers.intercom.com/building-apps/docs/authorization#section-how-to-get-an-access-token>`_.

To specify an API version, follow `these instructions <https://developers.intercom.com/building-apps/docs/api-versioning>`_ to do so through Intercom's Developer Hub.
The default will be the latest stable version. The Intercom app works on versions 1.2 or later.

How to set up the slack app
###########################

The slack endpoint API requires a bearer token, obtained by going through the slack oauth authentication process. Only one path through the process is supported by the slack app: manually installing a custom integration.

To obtain the bearer token, an administrator of the slack workspace must create a custom slack app, add the ``admin`` permission scope to the custom app, and install the app to the target workspace.

Step by step:

   1. Visit the `Create a Slack app <https://api.slack.com/apps/new>`_ page, and in the ``Create a Slack App`` dialog box fill in the App Name field with whatever you like and the select the target workspace from the ``Development Slack Workspace`` dropbdown box. Click ``Create App``.
   2. On the ``Basic Information`` page of the app you just created, scroll to and click on ``OAuth & Permissions`` on the left hand sidebar.
   3. Scroll to the ``Scopes`` section, click on the dropdown box under ``Select Permission Scopes``, and type ``admin`` to bring up the administrator scope (labeled ``Administer the workspace``). Select it, then click ``Save changes``.
   4. Scroll to the top of that same page and click on ``Install App to Workspace``. Click ``Authorize`` on the next dialog. You should be returned to the ``OAuth & Permissions`` page.
   5. The bearer token is the string labeled with ``OAuth Access Token`` and beginning with ``xoxp-``. It's what's needed to authorize the Slack StreamAlert app.


How to update necessary dependencies
####################################


Building Dependencies Using EC2
===============================

An EC2 instance that resembles the AWS Lambda environment must be launched.
This should use the Amazon Linux AMI, documented `here <http://docs.aws.amazon.com/lambda/latest/dg/current-supported-versions.html>`_.

If you are unfamiliar with EC2 instances and how to launch/connect to them, visit this `User Guide <http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EC2_GetStarted.html>`_.


ssh to ec2 instance
+++++++++++++++++++

.. code-block:: bash

  # ssh to ec2 instance
  $ ssh -i /path/to/<private-key>.pem ec2-user@public.dns.address

on ec2 instance
+++++++++++++++

.. code-block:: bash

  # Remove any previous caches
  $ rm -rf $HOME/.cache/pip/

  # Create and source venv
  $ virtualenv -p python3.7 $HOME/venv
  $ source $HOME/venv/bin/activate

  # Upgrade pip and setuptools (they are super old)
  $ pip install --upgrade pip setuptools

  # Make a temp build directory and temp pip install directory
  $ mkdir $HOME/build_temp $HOME/pip_temp

  # Install all of the dependencies to this directory
  $ pip install boxsdk[jwt]==2.6.1 --build $HOME/build_temp/ --target $HOME/pip_temp

  # Replace the `boxsdk[jwt]==2.6.1` below with the desired package & version
  # For example, the following would update the aliyun dependencies:
  # pip install aliyun-python-sdk-actiontrail==2.0.0 --build $HOME/build_temp/ --target $HOME/pip_temp

  # Change into the install directory
  $ cd $HOME/pip_temp

  # Cleanup any pyc files
  $ find . -name '*.pyc' | xargs rm -rf

  # Zip it all up
  $ zip -r pip.zip .

  # Exit the ssh session
  $ exit

back on local system
++++++++++++++++++++

.. code-block:: bash

  # scp to local host's current directory
  $ scp -i /path/to/<private-key>.pem ec2-user@public.dns.address:~/pip_temp/pip.zip .

Building Dependencies Using Vagrant
===================================

There is a `Vagrantfile <https://github.com/airbnb/streamalert/blob/release-3-0-0/Vagrantfile>`_ located in the root of the StreamAlert repository. This file can be used to spin up a virtual machine and build dependencies for the box sdk or aliyun sdk.

Install Vagrant
+++++++++++++++

Please visit the `Vagrant download page <https://www.vagrantup.com/downloads.html>`_ for more information on Vagrant. It is recommended to install the latest version of Vagrant.

Start the Virtual Machine
+++++++++++++++++++++++++

.. code-block:: bash

  # It may take few minutes to start the virtual machine for the first time, depending on your network speed
  $ vagrant up

SSH and Build Dependencies
++++++++++++++++++++++++++

.. code-block:: bash

  $ vagrant ssh

  # make sure you create virtual environment with python3.7
  $ which python3.7

  # Create virtual environment using virtualenvwrapper which is pre-installed
  $ mkvirtualenv -p /usr/bin/python3.7 test_venv

  # upgrade pip and setuptools if neccessary
  $ pip install --upgrade pip setuptools

  $ mkdir $HOME/build_temp $HOME/pip_temp
  $ pip install boxsdk[jwt]==2.6.1 --build $HOME/build_temp/ --target $HOME/pip_temp

  # Replace the `boxsdk[jwt]==2.6.1` below with the desired package & version
  # For example, the following would update the aliyun dependencies:
  # pip install aliyun-python-sdk-actiontrail==2.0.0 --build $HOME/build_temp/ --target $HOME/pip_temp

  $ cd $HOME/pip_temp
  $ find . -name '*.pyc' | xargs rm -rf

  # Install zip package
  $ sudo apt-get install zip
  $ zip -r pip.zip .

Copy the Dependencies Locally
+++++++++++++++++++++++++++++

Copy the `pip.zip` file from the virtual machine to the local host.

.. code-block:: bash

  $ cp pip.zip /vagrant/streamalert/apps/_apps/boxsdk[jwt]==2.6.1_dependencies.zip
  $ exit  # exit the session

Stop the Virtual Machine
++++++++++++++++++++++++

Suspend the Vagrant virtual machine after you are finished building and copying dependencies.

.. code-block:: bash

  $ vagrant suspend

Destroy the VM
++++++++++++++

Optionally, destroy the Vagrant virtual machine to free up disk space.

.. code-block:: bash

  $ vagrant destroy
