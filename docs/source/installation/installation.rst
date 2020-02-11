******************************
Installation
******************************

This section specifies the installation process for the VON Anchor package. It assumes an Ubuntu distribution on version 16.04 or higher.

.. _install_von_base:

Install Package von_base
******************************

On the host, issue:

.. code-block:: bash

    $ sudo apt update
    $ sudo apt upgrade
    $ cd
    $ git clone https://github.com/PSPC-SPAC-buyandsell/von_base.git
    $ cd von_base
    $ sudo ./setup
    $ exit

to install the ``von_base`` package and then exit the shell (to pick up ``docker`` group membership). The operation:

- installs operating system packages
- creates the pipenv virtual environment in the operator's home directory
- installs docker and docker-compose
- builds the indy node pool image
- creates the ``indy_pool_network`` docker network
- installs the ``libindy.so`` binary to ``/usr/lib/``.

Once this installation process completes (it takes a long time), the ``von_base`` package itself becomes extraneous except for reference documentation. All installed binary conent is extrinsic to the package.

Before proceeding with any docker operations within the same shell, logout:

.. code-block:: bash

    $ exit

and log back in again as the operator at the prompt to pick up the new ``docker`` group assignment. Test the state of the installation with test scripts as per :ref:`test_von_base`.

.. _test_von_base:

Test Package von_base
******************************

The test harness to check successful installation of the ``von_base`` resides at ``von_base/test/test_base``. It is a bash script echoing ``0`` if the installation appears successful and non-zero output otherwise. To run the test, issue at the prompt:

.. code-block:: bash

    $ cd
    $ cd von_base/test
    $ pipenv run test_base

.. _install_von_anchor:

Install Package von_anchor
******************************

This section outlines the independent installation of the ``von_anchor`` package. If relying packages install the package as a dependency, this step becomes redundant.

.. _install_von_anchor_pypi:

From pypi to pipenv Virtual Environment
+++++++++++++++++++++++++++++++++++++++

On the host, issue:

.. code-block:: bash

    $ cd
    $ pipenv install von_anchor

to install the ``von_anchor`` package in the pipenv virtual environment. This operation installs only python source code.

.. _install_von_anchor_github:

Full Installation from github
+++++++++++++++++++++++++++++++++++++++

On the host, issue:

.. code-block:: bash

    $ cd
    $ git clone https://github.com/PSPC-SPAC-buyandsell/von_anchor.git
    $ pipenv install -r von_anchor/requirements.txt

to install the ``von_anchor`` package complete with unit tests and requirement setup in the pipenv virtual environment.
