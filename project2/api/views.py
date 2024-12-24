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
    

@csrf_exempt    
@api_view(['POST'])
@permission_classes([AllowAny])  # Allows all to access the endpoint
def login_user(request):
    try:
        # Extract encrypted data from the request payload
        encrypted_data = request.data.get("data")
        logger.debug(f"Received data from project1: {encrypted_data}")  # Log received data

        if not encrypted_data:  # If data is not present, return an error
            return JsonResponse({"message": "data not found"}, status=status.HTTP_400_BAD_REQUEST)

        # Decrypt incoming data
        decrypted_data = f.decrypt(encrypted_data.encode()).decode()
        data = json.loads(decrypted_data)
        username = data.get("username")  # Retrieve username
        password = data.get("password")  # Retrieve password

        if not username or not password:  # Validate presence of username and password
            return JsonResponse({'message': 'Invalid username or password'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Get user from username
            user = User.objects.get(username=username)
            if not user.check_password(password):  # Validate password
                return JsonResponse({'message': 'Invalid username or password'}, status=status.HTTP_400_BAD_REQUEST)

            # Retrieve or create bank account
            try:
                bank_account = BankAccount.objects.get(user=user)
            except BankAccount.DoesNotExist:
                # If bank account doesn't exist, create one with encrypted fields
                account_number = ''.join([str(random.randint(0, 9)) for _ in range(12)])

                initial_balance = decimal.Decimal('500.00')
                encrypted_balance = f.encrypt(str(initial_balance).encode()).decode()

                bank_account = BankAccount.objects.create(
                    user=user,
                    account_number=account_number,
                    balance=encrypted_balance,
                    bank_name="My Bank"
                )  # Create bank account

            # Serialize user data
            serializer = SerializeBankAccount(bank_account)

            # Generate tokens
            refresh = RefreshToken.for_user(user)
            access = str(refresh.access_token)

            # Prepare response data, including manually encrypted fields
            response_data = {
                "access": access,
                "refresh": str(refresh),
                "message": "Login successful",
                "user_id": user.id,
                "username": user.username,
                "bank_account": {
                    # Include manually encrypted fields without passing through the serializer
                    "balance": bank_account.balance,  # Already encrypted
                    "account_number": bank_account.account_number,  # Already encrypted
                    **serializer.data,  # Include other fields from the serializer
                },
            }

            # Encrypt response data except already-encrypted fields
            encrypted_response_data = f.encrypt(json.dumps(response_data).encode()).decode()

            # Return encrypted response
            return JsonResponse({"data": encrypted_response_data}, status=status.HTTP_200_OK)

        except User.DoesNotExist:  # If user not found
            return JsonResponse({'message': 'Invalid username or password'}, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:  # Handle decryption or other errors
        logger.error("Error during login_user in project 2", exc_info=True)
        return JsonResponse({"message": "error decrypting data"}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([IsAuthenticated])  # Must be authenticated
def make_transfer(request):
    try:
        encrypted_data = request.data.get('data')  # retrieve encrypted data from body
        logger.info(f"Received encrypted data from project1: {encrypted_data}")
        if not encrypted_data:  # if data is not found
            return JsonResponse({"message": "data not found"}, status=status.HTTP_400_BAD_REQUEST)

        decrypted_data = f.decrypt(encrypted_data.encode()).decode()  # decrypt data
        logger.info(f"Received decrypted data from project1: {decrypted_data}")
        data = json.loads(decrypted_data)  # load decrypted data as json
        sender_username = data.get("sender_username")  # extract sender username
        receiver_username = data.get("receiver_username")  # extract receiver username
        amount = data.get("amount")  # extract amount
        receiver_account_number = data.get('receiver_account_number')  # get receiver account number

        # Check if essential fields are missing
        if not sender_username or not receiver_username or not amount or not receiver_account_number:
            return JsonResponse({"message": "sender_username, receiver_username, or amount or receiver account number not found"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            amount = decimal.Decimal(amount)  # convert amount to decimal value
        except Exception:  # if not a valid decimal number
            return JsonResponse({"message": "Invalid amount"}, status=status.HTTP_400_BAD_REQUEST)

        if amount <= 0:  # amount has to be above 0
            return JsonResponse({"message": "Amount must be greater than zero"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            sender = User.objects.get(username=sender_username)  # get sender object
            receiver = User.objects.get(username=receiver_username)  # get receiver object
            sender_account = BankAccount.objects.get(user=sender)  # get sender bank account object

            # Decrypt sender's balance
            decrypted_sender_balance = f.decrypt(sender_account.balance.encode()).decode()
            sender_account_balance = decimal.Decimal(decrypted_sender_balance)

            if sender_account_balance < amount:  # if balance is insufficient
                return JsonResponse({"message": "Insufficient balance"}, status=status.HTTP_400_BAD_REQUEST)

            try:
                receiver_account = BankAccount.objects.get(account_number=receiver_account_number)  # get receiver bank account object
                # Decrypt receiver's balance
                decrypted_receiver_balance = f.decrypt(receiver_account.balance.encode()).decode()
                receiver_account_balance = decimal.Decimal(decrypted_receiver_balance)

            except BankAccount.DoesNotExist:
                logger.error(f"Bank account for receiver with account number {receiver_account_number} does not exist in project 2")
                return JsonResponse({"message": "Receiver bank account does not exist"}, status=status.HTTP_400_BAD_REQUEST)

            # Perform transfer
            sender_account_balance -= amount  # deduct money from sender account
            receiver_account_balance += amount  # add money to receiver

            encrypted_sender_balance = f.encrypt(str(sender_account_balance).encode()).decode()
            encrypted_receiver_balance = f.encrypt(str(receiver_account_balance).encode()).decode()

            # Update bank account balances
            sender_account.balance = encrypted_sender_balance
            receiver_account.balance = encrypted_receiver_balance

            sender_account.save()  # save sender account
            receiver_account.save()  # save receiver account

            encrypted_amount = f.encrypt(str(amount).encode()).decode()
            encrypted_receiver_account = f.encrypt(str(receiver_account_number).encode()).decode()

            # Create transaction record
            transaction = Transaction.objects.create(account=sender_account, amount=encrypted_amount,
                                                     receiver=receiver, receiver_account=encrypted_receiver_account)
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                f"user_{receiver.id}",
                {
                    "type": "send_notification",
                    "message": f"{sender_username} has transferred {amount} to you",  # Updated message to provide more information
                    "sender": sender_username,
                    "amount": str(amount),
                    "receiver_id": receiver.id
                }
            )
            logger.info(f"Notification sent to user_{receiver.id}")
            return JsonResponse({'message': 'Transfer successful in project 2'}, status=status.HTTP_200_OK)

        except BankAccount.DoesNotExist:  # if bank account does not exist
            logger.error("Bank account for sender does not exist in project 2", exc_info=True)
            return JsonResponse({"message": "Bank account does not exist"}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:  # if user does not exist
            logger.error("User does not exist in project 2", exc_info=True)
            return JsonResponse({"message": "User does not exist"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error("Failed to make transaction. Try again later in project 2", exc_info=True)
            return JsonResponse({"message": "Failed to make transaction. Try again later"}, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        logger.error("Error in decrypting data in make_transfer in project 2", exc_info=True)
        return JsonResponse({"message": "Error decrypting data"}, status=status.HTTP_400_BAD_REQUEST)




@api_view(['GET'])
@permission_classes([IsAuthenticated])  # Requires authentication
def show_transactions(request):
    try:
        token = request.headers.get('Authorization').split()[1]  # Extract authorization token
        auth = JWTAuthentication()  # Initialize JWT authentication
        validated_token = auth.get_validated_token(token)  # Validate token
        logger.debug(f"Token is valid for user: {validated_token['user_id']}")  # Log successful token validation
    except Exception as e:  # Handle token validation failure
        logger.error(f"Token validation failed: {e}", exc_info=True)
        return JsonResponse({'error': 'Unauthorized'}, status=401)

    try:
        user_id = validated_token['user_id']
        user = User.objects.get(id=user_id)
        account = BankAccount.objects.get(user=user)  # Retrieve the user's bank account
        paginator = CustomPagination()
        transactions = Transaction.objects.filter(account=account).order_by('-created_at')  # Retrieve user transactions
        result_page = paginator.paginate_queryset(transactions, request)  # Paginate the results

        # Prepare the response data
        response_data = []
        for transaction in result_page:
            # Create a dictionary for each transaction with encrypted fields, except 'amount'
            transaction_data = {
                "id": f.encrypt(str(transaction.id).encode()).decode(),
                "account_id": f.encrypt(str(transaction.account.id).encode()).decode(),
                "sender": f.encrypt(transaction.account.user.username.encode()).decode(),
                "receiver": f.encrypt(transaction.receiver.username.encode()).decode(),
                "receiver_account": transaction.receiver_account,
                "amount": transaction.amount,  # Keep the amount as stored (already encrypted)
                "created_at": f.encrypt(transaction.created_at.isoformat().encode()).decode(),
                "updated_at": f.encrypt(transaction.updated_at.isoformat().encode()).decode(),
            }
            response_data.append(transaction_data)

        # Serialize the response data into a JSON string
        serialized_data = json.dumps(response_data)

        # Encrypt the entire serialized JSON string
        encrypted_response = f.encrypt(serialized_data.encode()).decode()

        logger.info(f"Encrypted transactions: {encrypted_response}")

        return JsonResponse({'data': encrypted_response}, status=status.HTTP_200_OK)
    except Exception as e:
        logger.error("Failed to show transactions, try again later in project 2", exc_info=True)
        return JsonResponse({"message": "Failed to show transactions, try again later"}, status=status.HTTP_400_BAD_REQUEST)


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
            account_number = ''.join([str(random.randint(0, 9)) for _ in range(12)])

            initial_balance = decimal.Decimal('500.00')
            encrypted_balance = f.encrypt(str(initial_balance).encode()).decode

            bank_account = BankAccount.objects.create(
                user=user,
                account_number=account_number,
                balance=encrypted_balance,
                bank_name="My Bank"
            ) # create bank account
            return JsonResponse({"message":"user registered in project2"},status=status.HTTP_201_CREATED)
        except Exception as e: # if there was a general error in the operation
            logger.error("Error during user registration in project 2", exc_info=True)
            return JsonResponse({'message':'username already exists in project2'},status=status.HTTP_400_BAD_REQUEST)
    except Exception as e: # if there was an error decrypting the data
        logger.error("Error during decrypting data in project 2", exc_info=True)
        return JsonResponse({"message":"error decrypting data"},status=status.HTTP_400_BAD_REQUEST)
    
@api_view(['GET'])
@authentication_classes([])  # No authentication class required for now
def get_transactions_api(request):
    try:
        # Validate the Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            logger.error("Authorization header is missing or invalid")
            return JsonResponse({"message": "Authorization header is missing or invalid"}, status=status.HTTP_401_UNAUTHORIZED)
        
        # Extract access token
        access_token = auth_header.split(' ')[1]
        
        # Prepare headers for the request to Project 2
        headers = {
            'Authorization': f"Bearer {access_token}",
            'Content-Type': 'application/json'
        }
        
        # Get the page query parameter
        page = request.GET.get('page', 1)

        # Make the request to Project 2's transactions API
        response = requests.get(f"{PROJECT2_URL}/api/transactions/?page={page}", headers=headers)

        if response.status_code == status.HTTP_200_OK:
            data = response.json()

            # Ensure 'data' key contains the encrypted string
            encrypted_data = data.get('data')
            if not isinstance(encrypted_data, str):
                logger.error(f"Invalid data type for 'data': {type(encrypted_data)}")
                return JsonResponse({'message': 'Invalid data format from Project 2'}, status=status.HTTP_400_BAD_REQUEST)

            try:
                # Decrypt the encrypted data string
                decrypted_data = f.decrypt(encrypted_data.encode()).decode()  # Ensure it's decoded from bytes to string
                transactions = json.loads(decrypted_data)  # Parse the decrypted JSON string into a list of transactions
                
                # Decrypt individual fields in each transaction
                for transaction in transactions:
                    for field in transaction:
                        if isinstance(transaction[field], str) and transaction[field].startswith("gAAAAA"):  # Check if it's encrypted
                            try:
                                transaction[field] = f.decrypt(transaction[field].encode()).decode()  # Decrypt the field
                            except Exception as e:
                                logger.error(f"Error decrypting field '{field}': {e}", exc_info=True)
                                transaction[field] = None  # Set to None or keep as is if decryption fails

                logger.info(f"Decrypted transactions: {transactions}")
                return JsonResponse({'data': transactions}, status=status.HTTP_200_OK)
            except Exception as e:
                logger.error("Error decrypting data in get_transactions_api", exc_info=True)
                return JsonResponse({"message": "Error decrypting data"}, status=status.HTTP_400_BAD_REQUEST)
        else:
            logger.error("Failed to get transactions with status code: %s, and response: %s", response.status_code, response.text)
            return JsonResponse({"message": "Failed to get transactions"}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        logger.error("Error occurred in get_transactions_api", exc_info=True)
        return JsonResponse({"message": "Failed to get transactions, try again later"}, status=status.HTTP_400_BAD_REQUEST)
