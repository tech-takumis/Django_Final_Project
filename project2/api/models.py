from django.db import models
from django.contrib.auth import get_user_model
import random
import time

User = get_user_model()

class BankAccount(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    account_number = models.CharField(max_length=100)
    balance = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    bank_name = models.CharField(max_length=100)
    
    def __str__(self):
        return f"Account {self.account_number} - {self.bank_name}"

class Transaction(models.Model):
    def generate_transaction_id():
      return str(int(time.time()*1000))+ str(random.randint(1000,9999))
    transaction_id = models.CharField(max_length=255, unique=True,editable=False,default=generate_transaction_id)
    account = models.ForeignKey(BankAccount, on_delete=models.CASCADE, related_name="sent_transaction")
    amount = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name="received_transaction")
    receiver_account = models.TextField()  # Add receiver account number

    def __str__(self):
        return f"ID: {self.transaction_id}, Sender: {self.account.user}, Receiver: {self.receiver}, Amount: {self.amount}"