from django.db import models
from django.contrib.auth.models import User

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
    account = models.ForeignKey(BankAccount, on_delete=models.CASCADE,related_name="sent_transaction")
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    receiver = models.ForeignKey(User, on_delete=models.CASCADE,related_name="received_transaction")

    def __str__(self):
        return f"Sender: {self.account.user}, Receiver: {self.receiver}, Amount: {self.amount}"