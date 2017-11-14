How to update boxsdk dependencies
#################################


Create an EC2 Instance
======================

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
  $ rm -rf ~/.cache/pip/

  # Create and source venv
  $ virtualenv ~/venv
  $ source ~/venv/bin/activate

  # Upgrade pip and setuptools (they are super old)
  $ pip install --upgrade pip setuptools

  # Make a temp build directory and temp pip install directory
  $ mkdir ~/build_temp
  $ mkdir ~/pip_temp

  # Install all of the dependencies to this directory
  # Replace the `boxsdk[jwt]==2.0.0a11` below with the desired package & version
  $ python -c "import pip; pip.main(['install', 'boxsdk[jwt]==2.0.0a11', '--build', '~/build_temp/',  '--target', '~/pip_temp'])"

  # Change into the install directory
  $ cd ~/pip_temp

  # Cleanup any pyc files
  $ find . -name '*.pyc' | xargs rm -rf

  # Zip it all up
  $ zip -r pip.zip * .*

  # Exit the ssh session
  $ exit

back on local system
++++++++++++++++++++

.. code-block:: bash

  # scp to local host's current directory
  $ scp -i /path/to/<private-key>.pem ec2-user@public.dns.address:~/pip_temp/pip.zip .
