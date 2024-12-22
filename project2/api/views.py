from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth.models import User
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework import status
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from .models import BankAccount, Transaction
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
import json
import logging
from rest_framework.pagination import PageNumberPagination
from .serializer import SerializeTransactions, SerializeBankAccount, SerializeUser

logger = logging.getLogger(__name__)

f = settings.FERNET # initialized key in settings.py

class CustomPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 100


@api_view(['POST'])
@permission_classes([IsAuthenticated])  # Optional, if JWT validation is handled manually
def logout_user(request):
    try:
        # Extract refresh token from the request
        refresh_token = request.data.get("refresh")

        if not refresh_token:
            return JsonResponse(
                {"message": "Refresh token is required"}, status=status.HTTP_400_BAD_REQUEST
            )

        # Attempt to blacklist the token
        token = RefreshToken(refresh_token)
        token.blacklist()

        return JsonResponse({'message': 'Logout successful'}, status=status.HTTP_205_RESET_CONTENT)
    
    except (TokenError, InvalidToken) as e:
        logger.error("Invalid or expired token during logout in project2", exc_info=True)
        return JsonResponse({"message": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        logger.error("Error during logout in project2", exc_info=True)
        return JsonResponse({"message": "Failed to logout user"}, status=status.HTTP_400_BAD_REQUEST)
    
        
@csrf_exempt    
@api_view(['POST'])
@permission_classes([AllowAny])
def login_user(request):
    try:
        encrypted_data = request.data.get("data")
        logger.debug(f"Receive data from project1: {encrypted_data}")
        if not encrypted_data:
            return JsonResponse({"message": "data not found"}, status=status.HTTP_400_BAD_REQUEST)

        # Decrypt data
        decrypted_data = f.decrypt(encrypted_data.encode()).decode()
        data = json.loads(decrypted_data)
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return JsonResponse({'message': 'Invalid username or password'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(username=username)
            if not user.check_password(password):
                return JsonResponse({'message': 'Invalid username or password'}, status=status.HTTP_400_BAD_REQUEST)

            # Generate tokens
            refresh = RefreshToken.for_user(user)
            access = str(refresh.access_token)

            return JsonResponse({
                "access": access,
                "refresh": str(refresh),
                "message": "Login successful"
            }, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return JsonResponse({'message': 'Invalid username or password'}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        logger.error("Error during login user in project 2", exc_info=True)
        return JsonResponse({"message": "error decrypting data"}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def register_user(request):
    try:
        encrypted_data = request.data.get("data")
        if not encrypted_data:
            return JsonResponse({"message":"data not found"},status=status.HTTP_400_BAD_REQUEST)

        decrypted_data= f.decrypt(encrypted_data.encode()).decode()
        data = json.loads(decrypted_data)
        username = data.get("username")
        password = data.get("password")
        email = data.get("email")

        if not username or not password or not email:
            return JsonResponse({"message":"username or password or email not found"},status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.create_user(username=username, password=password,email=email)
            bank_account = BankAccount.objects.create(user=user,account_number=str(user.id),balance=0,bank_name="My Bank")
            return JsonResponse({"message":"user registered in project2"},status=status.HTTP_201_CREATED)
        except Exception as e:
            logger.error("Error during user registration in project 2", exc_info=True)
            return JsonResponse({'message':'username already exists in project2'},status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        logger.error("Error during decrypting data in project 2", exc_info=True)
        return JsonResponse({"message":"error decrypting data"},status=status.HTTP_400_BAD_REQUEST)
        




        
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def make_transfer(request):
    try:
        encrypted_data = request.data.get('data')
        if not encrypted_data:
            return JsonResponse({"message":"data not found"},status=status.HTTP_400_BAD_REQUEST)

        decrypted_data= f.decrypt(encrypted_data.encode()).decode()
        data = json.loads(decrypted_data)
        sender_username = data.get("sender_username")
        receiver_username = data.get("receiver_username")
        amount = data.get("amount")

        if not sender_username or not receiver_username or not amount:
            return JsonResponse({"message":"sender_username,receiver_username, or amount not found"},status=status.HTTP_400_BAD_REQUEST)
        try:
            amount=float(amount)
        except:
            return JsonResponse({"message":"Invalid amount"},status=status.HTTP_400_BAD_REQUEST)
        if amount <=0:
            return JsonResponse({"message":"Amount must be greater than zero"},status=status.HTTP_400_BAD_REQUEST)
        try:
            sender = User.objects.get(username=sender_username)
            receiver = User.objects.get(username=receiver_username)
            sender_account = BankAccount.objects.get(user=sender)
            if sender_account.balance < amount:
                return JsonResponse({"message":"Insufficient balance"},status=status.HTTP_400_BAD_REQUEST)
            receiver_account = BankAccount.objects.get(user=receiver)
            
            # perform transfer
            sender_account.balance -= amount
            receiver_account.balance += amount

            sender_account.save()
            receiver_account.save()

            transaction = Transaction.objects.create(account=sender_account,amount=amount,transaction_type="transfer",receiver=receiver)

            return JsonResponse({'message':'Transfer successfull in project 2'},status=status.HTTP_200_OK)
        except BankAccount.DoesNotExist:
            logger.error("bank account does not exists in project 2", exc_info=True)
            return JsonResponse({"message":"bank account does not exists"},status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            logger.error("user does not exists in project 2", exc_info=True)
            return JsonResponse({"message":"user does not exists"},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error("Failed to make transaction try again later in project 2", exc_info=True)
            return JsonResponse({"message":"Failed to make transaction try again later"},status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        logger.error("Error in decrypting data in make_transfer in project 2", exc_info=True)
        return JsonResponse({"message":"error decrypting data"},status=status.HTTP_400_BAD_REQUEST)
    

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def show_transactions(request):
    try:
        token = request.headers.get('Authorization').split()[1]
        auth = JWTAuthentication()
        validated_token = auth.get_validated_token(token)
        logger.debug(f"Token is valid for user: {validated_token['user_id']}")
    except Exception as e:
        logger.error(f"Token validation failed: {e}", exc_info=True)
        return JsonResponse({'error': 'Unauthorized'}, status=401)

@api_view(['GET'])
@permission_classes([AllowAny])
def show_users(request):
    try:
        paginator = CustomPagination()
        users = User.objects.all()
        result_page = paginator.paginate_queryset(users, request)
        serializer = SerializeUser(result_page,many=True)
        encrypted_data = f.encrypt(json.dumps(serializer.data).encode()).decode()
        return paginator.get_paginated_response({"data":encrypted_data})
    except Exception as e:
        logger.error("Failed to show users try again later in project 2", exc_info=True)
        return JsonResponse({"message":"Failed to show users try again later"},status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([AllowAny])
def show_accounts(request):
    try:
        paginator = CustomPagination()
        accounts = BankAccount.objects.all()
        result_page = paginator.paginate_queryset(accounts, request)
        serializer = SerializeBankAccount(result_page,many=True)
        encrypted_data = f.encrypt(json.dumps(serializer.data).encode()).decode()
        return paginator.get_paginated_response({"data":encrypted_data})
    except Exception as e:
        logger.error("Failed to show accounts try again later in project 2", exc_info=True)
        return JsonResponse({"message":"Failed to show accounts try again later"},status=status.HTTP_400_BAD_REQUEST)