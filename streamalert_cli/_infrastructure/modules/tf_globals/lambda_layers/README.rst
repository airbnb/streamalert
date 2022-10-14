How to Update Precompiled Dependencies
######################################

For dependencies included in zips to be usable with Lambda Layers, files must reside within a ``python`` directory. See the
AWS `documentation <https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html#configuration-layers-path>`_
for more information.


Building Dependencies Using EC2
===============================

An EC2 instance that resembles the AWS Lambda environment must be launched.
This should use the Amazon Linux AMI, documented `here <http://docs.aws.amazon.com/lambda/latest/dg/current-supported-versions.html>`_.

If you are unfamiliar with EC2 instances and how to launch/connect to them, visit this `User Guide <http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EC2_GetStarted.html>`_.


ssh into EC2 instance
+++++++++++++++++++++

.. code-block:: bash

  # ssh to ec2 instance
  $ ssh -i /path/to/<private-key>.pem ec2-user@public.dns.address


On EC2 Instance
+++++++++++++++

.. code-block:: bash

  # Remove any previous caches
  $ rm -rf $HOME/.cache/pip/

  # Create and source venv
  $ python3.10 -m venv $HOME/venv
  $ source $HOME/venv/bin/activate

  # Upgrade pip and setuptools (they are super old)
  $ pip install --upgrade pip setuptools

  # Make a temp build directory and temp pip install directory
  $ mkdir -p $HOME/build_temp $HOME/pip_temp/python

  # Install all of the dependencies to this directory
  $ pip install boxsdk[jwt]==2.6.1 --build $HOME/build_temp/ --target $HOME/pip_temp/python

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


Back On Local System
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

  # make sure you create virtual environment with python3.10
  $ which python3.10

  # Create and source venv
  $ python3.10 -m venv venv && source venv/bin/activate

  # upgrade pip and setuptools if neccessary
  $ pip install --upgrade pip setuptools

  $ mkdir -p $HOME/build_temp $HOME/pip_temp/python
  $ pip install boxsdk[jwt]==2.9.0 --build $HOME/build_temp/ --target $HOME/pip_temp/python

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

  $ cp pip.zip /vagrant/streamalert_cli/_infrastructure/modules/tf_globals/lambda_layers/boxsdk[jwt]==2.6.1_dependencies.zip
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
