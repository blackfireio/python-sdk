# Below is for backward compat. Will be removed after Deprecation period

from blackfire.hooks.django.middleware import BlackfireDjangoMiddleware
from blackfire.hooks.flask.middleware import BlackfireFlaskMiddleware
from blackfire.utils import get_logger


class FlaskMiddleware(BlackfireFlaskMiddleware):
    pass


class DjangoMiddleware(BlackfireDjangoMiddleware):
    pass


log = get_logger(__name__)

# log.warning(
#     "DeprecationWarning: FlaskMiddleware/DjangoMiddleware will be deprecated. Please use 'blackfire.patch_all' "
#     "or run your server via 'blackfire run --xyz'."
# )
