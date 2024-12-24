import os
from channels.routing import ProtocolTypeRouter, URLRouter
from django.core.asgi import get_asgi_application
from api import routing as api_routing
from api.middleware.jwt_auth import JWTAuthMiddleware

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'project2.settings')

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": JWTAuthMiddleware(
        URLRouter(
            api_routing.websocket_urlpatterns
        )
    ),
})