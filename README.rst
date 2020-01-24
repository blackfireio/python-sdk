Blackfire SDK for Python
========================

Blackfire Python SDK is a Python library that manages the Blackfire
Python Profiler and handles communication with Blackfire.io servers.

Read the official `Blackfire
documentation <https://blackfire.io/docs/index>`_ for more information.

Installation
------------

Please follow the official `Blackfire Installation
Guide <https://blackfire.io/docs/up-and-running/installation>`_.

Usage
-----

These examples and more can be found on the official `Blackfire Python
SDK documentation <https://blackfire.io/docs/integrations/python/sdk>`_.

Manual profiling
~~~~~~~~~~~~~~~~

Following is an example of manual profiling:

.. code:: python

   from blackfire import probe

   probe.initialize(client_id='xxxxx', client_token='xxxxx')
   probe.enable()
   foo()
   bar()
   baz()
   probe.end() # this will send all collected data Blackfire.io servers

You can view your profiles here on `your dashboard <https://blackfire.io/my/profiles>`_.

Aggregation of Traces
~~~~~~~~~~~~~~~~~~~~~

We can call ``enable()``/``disable()`` multiple times until we finally
call ``end()``.

.. code:: python

   from blackfire import probe

   probe.initialize()
   probe.enable()
   foo()
   probe.disable()
   probe.enable()
   bar()
   probe.disable()
   with probe.run():
       baz()

Profiling Python scripts via CLI
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Save below as ``foo.py``:

.. code:: python

   def foo():
       print('foo called!')

   foo()

Then run following:

.. code:: bash

   blackfire run python foo.py

Above command will run your script till end and uploads the resulting profile
to Blackfire. You profile will be available on `your dashboard <https://blackfire.io/my/profiles>`_.

Profiling Django via Middleware
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Read the `Django Integration
documentation <https://blackfire.io/docs/integrations/python/sdk>`_ on
the Blackfire website.

1. Install the `Blackfire Browser
   Extension <https://blackfire.io/docs/integrations/browsers/chrome>`_.

2. Add Blackfire middleware in your Django ``settings.py`` as following:

   .. code:: python

      MIDDLEWARE = [
          ...
          ...
          'blackfire.middleware.DjangoMiddleware',
      ]

3. Follow these
   `steps <https://blackfire.io/docs/cookbooks/profiling-http-via-browser>`_
   to profile via Browser.

Resources
---------

-  `Blackfire.io <https://blackfire.io>`_
-  `Blackfire Installation
   Guide <https://blackfire.io/docs/up-and-running/installation>`_
-  `Blackfire Python SDK
   documentation <https://blackfire.io/docs/integrations/python/sdk>`_
-  `Blackfire Django
   Integration <https://blackfire.io/docs/integrations/python/django>`_
