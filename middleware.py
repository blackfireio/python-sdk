# Below is for backward compat. Will be removed after Deprecation period

from blackfire.hooks.django.middleware import BlackfireDjangoMiddleware
from blackfire.hooks.flask.middleware import BlackfireFlaskMiddleware


class FlaskMiddleware(BlackfireFlaskMiddleware):
    pass


class DjangoMiddleware(BlackfireDjangoMiddleware):
    pass
