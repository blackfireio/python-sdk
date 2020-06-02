import importlib
import traceback
from blackfire.utils import function_wrapper



def _insert_middleware():
    print('insert our middleware called.')
    #from django.conf import settings
    #print(settings.MIDDLEWARE)


def patch():
    # TODO: if already imported print warning? I did not see anyone has done
    # similar thing?
    try:
        module = importlib.import_module('django.core.handlers.base')
        module.BaseHandler.load_middleware = function_wrapper(
            module.BaseHandler.load_middleware, pre_func=_insert_middleware
        )
        return True
    except:
        traceback.print_exc()
        return False
