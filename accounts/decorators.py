from django.contrib.auth.decorators import user_passes_test
from django.core.exceptions import PermissionDenied
from functools import wraps

def role_required(*roles):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if request.user.role not in roles:
                raise PermissionDenied("Vous n'avez pas la permission d'accéder à cette page")
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator