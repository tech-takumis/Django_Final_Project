from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    re_path(r'api/ws/transactions/',consumers.TransactionConsumer.as_asgi()), #Removed /api from the path
]