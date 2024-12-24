from rest_framework import serializers
from .models import BankAccount, Transaction
from django.contrib.auth.models import User


class SerializeTransactions(serializers.ModelSerializer):
    sender = serializers.CharField(source='account.user.username', read_only=True)
    receiver = serializers.CharField(source='receiver.username', read_only=True)
    class Meta:
        model = Transaction
        fields = ['id','sender','receiver','amount','created_at']

class SerializeBankAccount(serializers.ModelSerializer):
     user = serializers.CharField(source='user.username', read_only=True)
     class Meta:
        model = BankAccount
        fields = ['id','user','account_number','balance','bank_name']


class SerializeUser(serializers.ModelSerializer):
     class Meta:
          model = User
          fields = ['id','username','email']