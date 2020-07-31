def get_current_view_name(request):
    from django.urls import resolve

    try:
        return resolve(request.path).view_name
    except:
        pass
