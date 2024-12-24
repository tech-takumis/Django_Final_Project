from django.shortcuts import render
from django.http import JsonResponse
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework import status
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from django.contrib.auth import get_user_model
from cryptography.fernet import Fernet
import json
import logging
import random
import decimal
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

from .models import BankAccount, Transaction # Import the models
from rest_framework.pagination import PageNumberPagination #Import Pagination class
from .serializer import SerializeTransactions, SerializeBankAccount, SerializeUser # Import Serializer


logger = logging.getLogger(__name__) # Logger
f = Fernet(settings.ENCRYPTION_KEY) # Initialize Fernet for decryption

User = get_user_model() # Get the user model for authentication


class CustomPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 100



@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_user(request):
    try:
        # Extract refresh token from the request
        refresh_token = request.data.get("refresh")

        if not refresh_token:
            logger.error("Refresh token is missing in request body.")
            return JsonResponse(
                {"message": "Refresh token is required"}, status=status.HTTP_400_BAD_REQUEST
            )

         # Attempt to blacklist the token
        try:
            token = RefreshToken(refresh_token) # Create the object
            raw_token = str(token) # extract the raw token string from the object
            BlacklistedToken.objects.create(token=raw_token) #Pass the raw token string with the token parameter
        except Exception as e:
              logger.error(f"Invalid or expired token during logout in project2: {e}")
              return JsonResponse({"message": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)
        
        logger.info("User successfully logged out")
        return JsonResponse({'message': 'Logout successful'}, status=status.HTTP_205_RESET_CONTENT)
    
    except (TokenError, InvalidToken) as e:
        logger.error(f"Invalid or expired token during logout in project2: {e}")
        return JsonResponse({"message": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        logger.error(f"Error during logout in project2: {e}")
        return JsonResponse({"message": "Failed to logout user"}, status=status.HTTP_400_BAD_REQUEST)
    

# Project2 Login API
@csrf_exempt    
@api_view(['POST'])
@permission_classes([AllowAny]) # Allows all to access endpoint
def login_user(request):
    try:
        encrypted_data = request.data.get("data") # Extract encrypted data from the payload
        logger.debug(f"Receive data from project1: {encrypted_data}") # Log received data
        if not encrypted_data: # If not found, return an error
            return JsonResponse({"message": "data not found"}, status=status.HTTP_400_BAD_REQUEST)

        # Decrypt data
        decrypted_data = f.decrypt(encrypted_data.encode()).decode()
        data = json.loads(decrypted_data)
        username = data.get("username") # Retrieve username
        password = data.get("password") # retrieve password

        if not username or not password: # check if username and password is present
            return JsonResponse({'message': 'Invalid username or password'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(username=username) # get the user from the username
            if not user.check_password(password): #check if the password is correct
                return JsonResponse({'message': 'Invalid username or password'}, status=status.HTTP_400_BAD_REQUEST)

             # Check if user has bank account
            try:
                bank_account = BankAccount.objects.get(user=user) # if exist, then retrieve
            except BankAccount.DoesNotExist:
                # Create a default BankAccount for the user
                bank_account = BankAccount.objects.create(
                     user = user,
                     account_number=''.join([str(random.randint(0, 9)) for _ in range(12)]),  # generate a 12 digit random number as account number
                     balance=0.00,
                     bank_name="MyBank",
                    )
            # Generate tokens
            refresh = RefreshToken.for_user(user)
            access = str(refresh.access_token)
            serializer = SerializeBankAccount(bank_account)
            return JsonResponse({
                "access": access,
                "refresh": str(refresh),
                "message": "Login successful",
                "user_id": user.id,
                "username": user.username, 
                "bank_account": serializer.data
            }, status=status.HTTP_200_OK)
        except User.DoesNotExist: # if user not found
            return JsonResponse({'message': 'Invalid username or password'}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e: # if there is an error decrypting
        logger.error("Error during login user in project 2", exc_info=True)
        return JsonResponse({"message": "error decrypting data"}, status=status.HTTP_400_BAD_REQUEST)


# Project2 Transfer API
@api_view(['POST'])
@permission_classes([IsAuthenticated]) # Must be authenticated
def make_transfer(request):
    try:
        encrypted_data = request.data.get('data') # retrieve encrypted data from body
        if not encrypted_data: # if data is not found
            return JsonResponse({"message":"data not found"},status=status.HTTP_400_BAD_REQUEST)

        decrypted_data= f.decrypt(encrypted_data.encode()).decode() # decrypt data
        data = json.loads(decrypted_data) # load decrypted data as json
        sender_username = data.get("sender_username") # extract sender username
        receiver_username = data.get("receiver_username") # extract receiver username
        amount = data.get("amount") # extract amount
        receiver_account_number = data.get('receiver_account_number') #get receiver account number
        if not sender_username or not receiver_username or not amount or not receiver_account_number: # check if username, receiver and amount is present
            return JsonResponse({"message":"sender_username,receiver_username, or amount or receiver account number not found"},status=status.HTTP_400_BAD_REQUEST)
        try:
            amount=decimal.Decimal(amount) # convert amount to decimal value, we will no longer use float conversion
        except: # if not a float number
            return JsonResponse({"message":"Invalid amount"},status=status.HTTP_400_BAD_REQUEST)
        if amount <=0: # amount has to be above 0
            return JsonResponse({"message":"Amount must be greater than zero"},status=status.HTTP_400_BAD_REQUEST)
        try:
            sender = User.objects.get(username=sender_username) # get sender object
            receiver = User.objects.get(username=receiver_username) # get receiver object
            sender_account = BankAccount.objects.get(user=sender) # get sender bank account object
            if sender_account.balance < amount: # if balance is insufficient
                return JsonResponse({"message":"Insufficient balance"},status=status.HTTP_400_BAD_REQUEST)
            try:
                receiver_account = BankAccount.objects.get(account_number=receiver_account_number) # get receiver bank account object
            except BankAccount.DoesNotExist:
                  logger.error("bank account for receiver does not exists in project 2", exc_info=True)
                  return JsonResponse({"message":"Receiver bank account does not exists"},status=status.HTTP_400_BAD_REQUEST)
            
            # perform transfer
            sender_account.balance -= amount # remove money from sender account
            receiver_account.balance += amount # add money to receiver

            sender_account.save() # save sender account
            receiver_account.save() # save receiver account

            transaction = Transaction.objects.create(account=sender_account,amount=amount,receiver=receiver,receiver_account=receiver_account_number) # create transaction
            
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                 f"user_{receiver.id}",
                 {
                     "type": "send_notification",
                      "message": f"{sender_username} has transfered {amount} to you", #updated the messages so it provides more information.
                      "sender": sender_username,
                      "amount": str(amount),
                      "receiver_id": receiver.id
                  }
             )
            logger.info(f"Notification sent to user_{receiver.id}")
            return JsonResponse({'message':'Transfer successfull in project 2'},status=status.HTTP_200_OK)
        
        except BankAccount.DoesNotExist: # if bank account does not exist
            logger.error("bank account for sender does not exists in project 2", exc_info=True)
            return JsonResponse({"message":"bank account does not exists"},status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist: # if user does not exist
            logger.error("user does not exists in project 2", exc_info=True)
            return JsonResponse({"message":"user does not exists"},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error("Failed to make transaction try again later in project 2", exc_info=True)
            return JsonResponse({"message":"Failed to make transaction try again later"},status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        logger.error("Error in decrypting data in make_transfer in project 2", exc_info=True)
        return JsonResponse({"message":"error decrypting data"},status=status.HTTP_400_BAD_REQUEST)



# Project2 Get Transaction API
@api_view(['GET'])
@permission_classes([IsAuthenticated])  # Requires authentication
def show_transactions(request):
    try:
        token = request.headers.get('Authorization').split()[1] # split header into authorization token
        auth = JWTAuthentication() # initialize JWT authentication
        validated_token = auth.get_validated_token(token) # validate token
        logger.debug(f"Token is valid for user: {validated_token['user_id']}") # Log if the token was valid
    except Exception as e: # If token validation failed
        logger.error(f"Token validation failed: {e}", exc_info=True)
        return JsonResponse({'error': 'Unauthorized'}, status=401)

    try:
        user_id = validated_token['user_id']
        user = User.objects.get(id=user_id)
        account = BankAccount.objects.get(user=user) # if exist then retrieve the bank account
        paginator = CustomPagination()
        transactions = Transaction.objects.filter(account=account).order_by('-created_at') # get the user transaction and order it by creation time.
        result_page = paginator.paginate_queryset(transactions, request) # paginate the result set
        serializer = SerializeTransactions(result_page,many=True) # Serialize the transaction using the serializer class
        encrypted_data = f.encrypt(json.dumps(serializer.data).encode()).decode() # Encrypt data
        logger.debug(f"encrypted data: {encrypted_data}")

        return JsonResponse({'data':encrypted_data}, status=status.HTTP_200_OK) # Return a json response object with only the encrypted data
    except Exception as e:
         logger.error("Failed to show transaction try again later in project 2", exc_info=True)
         return JsonResponse({"message":"Failed to show transaction try again later"},status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([AllowAny]) # allow any to access the enpoint
def show_accounts(request):
    try:
        paginator = CustomPagination() # initialize the paginator
        accounts = BankAccount.objects.all() # get all bank accounts
        result_page = paginator.paginate_queryset(accounts, request) # paginate the account object
        serializer = SerializeBankAccount(result_page,many=True) # serialize the data
        encrypted_data = f.encrypt(json.dumps(serializer.data).encode()).decode() # encrypt data
        return paginator.get_paginated_response({"data":encrypted_data}) # return paginated response
    except Exception as e: # if any error occurs
        logger.error("Failed to show accounts try again later in project 2", exc_info=True)
        return JsonResponse({"message":"Failed to show accounts try again later"},status=status.HTTP_400_BAD_REQUEST)
    

@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny]) # Allows all to access the endpoint
def register_user(request):
    try:
        encrypted_data = request.data.get("data") # extract the data from the request
        if not encrypted_data: #if data is not present
            return JsonResponse({"message":"data not found"},status=status.HTTP_400_BAD_REQUEST)

        decrypted_data= f.decrypt(encrypted_data.encode()).decode() # decrypt the data
        data = json.loads(decrypted_data) # load the data into a json object
        username = data.get("username") # extract username
        password = data.get("password") # extract password
        email = data.get("email") # extract email
        first_name = data.get("first_name")
        last_name = data.get("last_name")
        middle_initial = data.get('middle_initial')

        if not username or not password or not email or not first_name or not last_name: # check for username, password and email
            return JsonResponse({"message":"username or password or email or full name not found"},status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.create_user(username=username, password=password,email=email,first_name=first_name,last_name=last_name) # create user
            bank_account = BankAccount.objects.create(user=user,
            account_number=''.join([str(random.randint(0, 9)) for _ in range(12)]),
            balance=decimal.Decimal('500.00'),
            bank_name="My Bank"
            ) # create bank account
            return JsonResponse({"message":"user registered in project2"},status=status.HTTP_201_CREATED)
        except Exception as e: # if there was a general error in the operation
            logger.error("Error during user registration in project 2", exc_info=True)
            return JsonResponse({'message':'username already exists in project2'},status=status.HTTP_400_BAD_REQUEST)
    except Exception as e: # if there was an error decrypting the data
        logger.error("Error during decrypting data in project 2", exc_info=True)
        return JsonResponse({"message":"error decrypting data"},status=status.HTTP_400_BAD_REQUEST)