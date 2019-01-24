******************************
VON Anchor Unit Tests
******************************

This section specifies the invocation of the unit tests of the full (from github) ``von_anchor`` installation, to validate its fitness.

.. _prereq_von_anchor:

Prerequisites
******************************

This section specifies the prerequisites to satisfy after installing the ``von_anchor`` package, prior to executing its unit tests.

Environment Variables
++++++++++++++++++++++++++++++

Export the following environment variables to operate the ``von_anchor`` unit tests:

- ``RUST_LOG=error`` - the log level for indy-sdk's underlying rust wrapper of the cryptographic library
- ``PIPENV_MAX_DEPTH=16`` - instructs ``pipenv`` to search up to 16 superdirectories to find its environment specification before constructing a new one in the local directory
- ``TEST_POOL_IP=10.0.0.2`` - specifies the test pool IP address.

Node Pool
++++++++++++++++++++++++++++++

This section discusses the operation of the node pool, which operates the distributed ledger, defaulting to the indy-sdk ``indy_pool`` docker container that implements the ``indy_pool_network`` docker network. The ``von_base`` package, on installation, builds this implementation on the host.

Note that if using the default implementation, stopping and restarrting the docker container implementing the node pool restores it to its pristine state after its genesis transactions. This action invalidates any wallet content generated over a prior node pool life.

The subsections below discuss when the node pool must be operating, and how to start and stop it.

.. _nodepool_test:

Necessity of Operation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The table below specifies which ``von_anchor`` unit tests require the node pool to be running.

.. csv-table::
   :header: "Unit Test", "Node Pool Operation Requirement?"
   :widths: 25, 75

    "test_a2a.py", "No"
    "test_anchors.py", "Yes"
    "test_cache.py", "No"
    "test_canon.py", "No"
    "test_encode.py", "No"
    "test_id_valid.py", "No"
    "test_pool.py", "Yes"
    "test_tails_load.py", "Yes"
    "test_wallet.py", "No"
    "op/test_sendnym.py", "Yes"

Table: Unit Tests by Node Pool Operation Requirement

.. _start_node_pool:

Starting
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To start the node pool, issue at the prompt:

.. code-block:: bash

    $ docker run -d --ip=10.0.0.2 --net=indy_pool_network indy_pool

at the bash prompt to start the container realizing the ``indy_pool_network`` docker network on a docker container running the ``indy_pool`` docker image. Recall that ``von_base`` installs this configuration on setup.

.. _check_node_pool:

Checking
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To check whether the default docker node pool is running, issue at the prompt:

.. code-block:: bash

    $ docker ps --filter ancestor=indy_pool --filter status=running --no-trunc | sed '1,1d' | awk '{print $1}'

and check the result; a docker hash implies that the pool is operational.

The check whether an external node pool is running, attempt to connect to one of its ports (typically, 9701-9708):

.. code-block:: bash

    $ telnet <test-pool-ip> 9702

where ``<test-pool-ip>`` represents the IP address.

.. _stop_node_pool:

Stopping
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To stop the default docker node pool, issue at the prompt:

.. code-block:: bash

    $ docker rm $(docker stop $(docker ps -aq))

at the bash prompt to stop and remove the container.

Unit Test Operation
******************************

This section specifies the operation of the VON anchor unit tests. These tests run on the pytest framework. The remainder of this section assumes:

- the installation of ``von_base`` as per :ref:`install_von_base`
- the successful test of ``von_base`` as per :ref:`test_von_base`
- the full installation of ``von_anchor`` from pypi as per :ref:`install_von_anchor_pypi`
- the fulfilment of prerequisites as per :ref:`prereq_von_anchor` (node pool necessity depends on choice of unit test as per :ref:`nodepool_test`).

Agent-to-Agent Utilities
+++++++++++++++++++++++++++++++++

This unit test starts from a JSON-LD DID document. It converts it to a ``DIDDoc`` object and, from this object, back to JSON-LD. The test checks that the output JSON matches the input.

To operate the test harness, issue at the prompt:

.. code-block:: bash

    $ cd
    $ cd von_anchor/test
    $ pipenv run pytest -s test_a2a.py

Cache Operation and Thread Safety
+++++++++++++++++++++++++++++++++

This unit test ensures that the schema cache can index by schema key or by transaction number. Additionally, it exercises the cache lock mechanism's thread safety (note that all caches share the strategy, testing any one tests them all).

To operate the test harness, issue at the prompt:

.. code-block:: bash

    $ cd
    $ cd von_anchor/test
    $ pipenv run pytest -s test_cache.py

Canonicalization
++++++++++++++++++++++++++++++

This unit test exercises canonicalization utilities for indy-sdk artifacts.

To operate the test harness, issue at the prompt:

.. code-block:: bash

    $ cd
    $ cd von_anchor/test
    $ pipenv run pytest -s test_canon.py

Claim Attribute Encoding
+++++++++++++++++++++++++++++++++

This unit test ensures that the claim attribute encoding mechanism satisfy's indy-sdk's specifications.

To operate the test harness, issue at the prompt:

.. code-block:: bash

    $ cd
    $ cd von_anchor/test
    $ pipenv run pytest -s test_encode.py

Identifier Validation
++++++++++++++++++++++++++++++

This unit test exercises identifier validation:

- wallet referents
- tails hashes
- distributed identifiers
- schema identifiers
- credential definition identifiers
- revocation registry identifiers.

To operate the test harness, issue at the prompt:

.. code-block:: bash

    $ cd
    $ cd von_anchor/test
    $ pipenv run pytest -s test_id_valid.py

Node Pool
+++++++++++++++++++++++++++++++++

This unit test exercises the configuration, opening and closing of ``NodePool`` objects, and the correctness of the associated ``Protocol`` enumeration's indy-node protocol selection.

It requires that the node pool be operational: check it as per :ref:`check_node_pool`; start if necessary as per :ref:`start_node_pool`.

To operate the test harness, issue at the prompt:

.. code-block:: bash

    $ cd
    $ cd von_anchor/test
    $ pipenv run pytest -s test_pool.py

Wallet
+++++++++++++++++++++++++++++++++

This unit test exercises the configuration, opening and closing of ``Wallet`` objects.

To operate the test harness, issue at the prompt:

.. code-block:: bash

    $ cd
    $ cd von_anchor/test
    $ pipenv run pytest -s test_wallet.py

Anchors
+++++++++++++++++++++++++++++++++

This unit test exercises anchor operation.

It requires that the node pool be operational: check it as per :ref:`check_node_pool`; start if necessary as per :ref:`start_node_pool`.

To operate the test harness, issue at the prompt:

.. code-block:: bash

    $ cd
    $ cd von_anchor/test
    $ pipenv run pytest -s test_anchors.py

Tails Load
+++++++++++++++++++++++++++++++++

This unit test exercises the operation of the external revocation registry builder posture for an issuer anchor.

It requires that the node pool be operational: check it as per :ref:`check_node_pool`; start if necessary as per :ref:`start_node_pool`.

To operate the test harness, issue at the prompt:

.. code-block:: bash

    $ cd
    $ cd von_anchor/test
    $ pipenv run pytest -s test_tails_load.py

Sendnym Operation
++++++++++++++++++++++++++++++++

This unit test exercises the operation of the operation script sending a cryptonym to the ledger.

It requires that the node pool be operational: check it as per :ref:`check_node_pool`; start if necessary as per :ref:`start_node_pool`.

To operate the test harness, issue at the prompt:

.. code-block:: bash

    $ cd
    $ cd von_anchor/test/op
    $ pipenv run pytest -s test_sendnym.py


Cleanup on Abend
********************************

The indy-sdk maintains state with files in the ``.indy_client/`` tree under the temporary and home directories. If an abnormal exit corrupts files in this tree, then on the next startup of objects that indy-sdk resolves to the same file names, indy-sdk will raise an exception. The indy-sdk can survive a corrupt file in the temporary directory, but sometimes not in the home directory.

To clear such a jam, an operator can issue the following sequence at the prompt:

.. code-block:: bash

    $ rm -rf ~/.indy_client

and then stop and start the node pool as per :ref:`stop_node_pool` and :ref:`start_node_pool`.
