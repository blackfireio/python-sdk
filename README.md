Blackfire SDK for Python
========================

Blackfire Python SDK is a Python library that manages the Blackfire Python
Profiler and handles communication with Blackfire.io servers.

Read the official [Blackfire documentation](https://blackfire.io/docs/index)
for more information.

Installation
------------

Please follow the official [Blackfire Installation
Guide](https://blackfire.io/docs/up-and-running/installation).

Usage
-----

These examples and more can be found on the official [Blackfire Python SDK
documentation](https://blackfire.io/docs/integrations/python/sdk)

### Manual profiling

Following is an example of manual profiling:

```python
from blackfire import probe

probe.initialize(client_id='xxxxx', client_token='xxxxx')
probe.enable()
foo()
bar()
baz()
probe.end() # this will send all collected data Blackfire.io servers
```

You can view your profiles here:
[https://blackfire.io/my/profiles](https://blackfire.io/my/profiles)

### Aggregation of Traces

We can call `enable()`/`disable()` multiple times until we finally call `end()`.

```python
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
```

### Profiling Python scripts via CLI

Save below as `foo.py`:

```python
def foo():
    print('foo called!')

foo()
```

Then run following:

```bash
blackfire run python foo.py
```

Above command will run your script till end and uploads the profile payload to
[https://blackfire.io/my/profiles](https://blackfire.io/my/profiles)

### Profiling Django via Middleware

Read the [Django Integration documentation](https://blackfire.io/docs/integrations/python/sdk) on the Blackfire website.

1. Install the [Blackfire Browser Extension](https://blackfire.io/docs/integrations/browsers/chrome).
2. Add Blackfire middleware in your Django `settings.py` as following:

   ```python
   MIDDLEWARE = [
       ...
       ...
       'blackfire.middleware.DjangoMiddleware',
   ]
   ```

3. Follow these [steps](https://blackfire.io/docs/cookbooks/profiling-http-via-browser) to
   profile via Browser.

Resources
---------

- [Blackfire.io](https://blackfire.io)
- [Blackfire Installation Guide](https://blackfire.io/docs/up-and-running/installation)
- [Blackfire Python SDK documentation](https://blackfire.io/docs/integrations/python/sdk)
- [Blackfire Django Integration](https://blackfire.io/docs/integrations/python/django)
