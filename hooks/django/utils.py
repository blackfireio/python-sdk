def get_current_view_name(request):
    try:
        from django.urls import resolve
    except:
        pass

    # 1.8 and below
    try:
        from django.core.urlresolvers import resolve
    except:
        pass

    try:
        return resolve(request.path).view_name
    except:
        pass
