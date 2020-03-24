Contributing
============

Installing Dependencies
-----------------------

Make sure you are running Python 3.7::

  $ python -V
  Python 3.7.x

Install:

1. `Pip <https://pip.pypa.io/en/stable/installing/>`_
2. `Terraform <https://www.terraform.io/intro/getting-started/install.html>`_

Fork the StreamAlert repository from the UI, and then clone it locally:

.. code-block:: bash

  $ git clone https://github.com/<your-username>/streamalert.git

Change into the cloned StreamAlert repo, and install Python dependencies:

.. code-block:: bash

  $ cd streamalert
  $ pip install -r requirements.txt

Modifying Dependencies
----------------------

If you modify the Python dependencies, you should do:

.. code-block:: bash

  $ pip install -r requirements-top-level.txt --upgrade
  $ pip freeze –r requirements-top-level.txt > requirements.txt

Making Changes
--------------

Checkout a new branch:

.. code-block:: bash

  git checkout -b <branch-name>

Make changes, add features, or fix bugs.

When writing commit messages, make sure to prefix with one of the following tags::

  [docs]              # changes to StreamAlert documentation
  [cli]               # streamalert_cli changes
  [terraform]         # terraform changes
  [core]              # changes with core streamalert classes used across lambda functions
  [testing]           # changes with testing infrastructure or processes
  [setup]             # StreamAlert development setup changes
  [config]            # streamalert config changes

The first line of your commit message should be short.  Use newlines to explain further::

  [tag] short description

  * longer explanation of what the change is
  * with added context

.. note:: Please squash your similar commits into one.  This keeps the repositories commit history easy to read.

Commit Squashing
~~~~~~~~~~~~~~~~

If all of your commits fall within the same tag, you can squash them during the pull request process via the Github UI.  If not, follow the steps below.

Scenario: You have unstaged changes that you want to add into your last commit::

  $ git add -u           # add all tracked files
  $ git commit --amend   # commit these changes to the last commit

Scenario: You have two commits you want to merge into one:

.. code-block:: bash

  $ git log --oneline
  c3dbbe9 [docs] add contributing guide
  f5b038e [docs] add streamalert authors
  04e52c1 [setup] add jinja2 to requirements.txt
  ...

In this case, let's merge the two ``[docs]`` commits:

.. code-block:: bash

  $ git rebase -i f5b038e~1
  pick f5b038e [docs] add streamalert authors
  squash c3dbbe9 [docs] add contributing guide

If your editor is `vim`, type `:wq` once you enter the above changes.

This will now open a new window to modify your combined commit message.  Make your edits, and exit once again.

After rebasing, you will need to force push your branch if it already exists upstream:

.. code-block:: bash

  $ git push origin <mybranch> -f

Tests
-----

Unit Testing
~~~~~~~~~~~~

StreamAlert contains unit tests for many parts of the code.  When making changes, you need to ensure that you do  not break existing functionality.  To run unit tests locally:

.. code-block:: bash

  # run this from the repo root
  $ nosetests -v tests/unit

Each test should end with ``... ok``, and finally you should see ``OK`` at the end.

If you are making changes which require unit test refactoring, please do so.

If you are adding features to existing classes with tests, you must add test cases to verify expected behavior.

Integration Testing
~~~~~~~~~~~~~~~~~~~

To verify StreamAlert works from end-to-end, locally, follow the testing instructions `here <https://streamalert.io/en/stable/testing.html#running-tests>`_.

Pull Request
------------

Once your code is ready for review, push the branch to your forked repository, and make a pull-request to the main ``airbnb/streamalert`` repo.

The title of your pull request should be a short description of your changes.

In your pull request body, use the following template::

  to: @airbnb/streamalert-maintainers

  size: small|medium|large
  resolves #1              # only add this if there's a relevant open issue related to this PR

  * summary of changes 1
  * summary of changes 2

All pull requests must pass continuous integration tests (nosetests) and receive a code review from one of the maintainers.
