import json
from channels.generic.websocket import AsyncJsonWebsocketConsumer
import logging


logger = logging.getLogger(__name__)

class TransactionConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        logger.info(f"Websocket connect from client: {self.channel_name}")
        logger.info(f"Attempting to add user to group: user_{self.scope['user'].id}")
        await self.accept()
        if self.scope["user"]:
            await self.channel_layer.group_add(f"user_{self.scope['user'].id}", self.channel_name)
            logger.info(f"User {self.scope['user'].id} added to group")

    async def disconnect(self, close_code):
        logger.info(f"websocket disconnect from client: {self.channel_name}")
        if self.scope["user"]:
            await self.channel_layer.group_discard(f"user_{self.scope['user'].id}", self.channel_name)

    async def send_notification(self,event):
        message = event['message']
        sender = event['sender']
        amount = event['amount']
        receiver_id = event['receiver_id']

        await self.send(text_data=json.dumps({
            'message': message,
             'sender':sender,
              'amount':amount,
               "receiver_id": receiver_id
        }))