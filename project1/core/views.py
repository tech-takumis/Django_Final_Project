from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth.models import User
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
import requests
import json
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

    
PROJECT2_URL = "http://localhost:8001"  # Replace with Project 2's URL
f = settings.FERNET # initialized key in settings.py

#Register
@api_view(['POST'])
@permission_classes([AllowAny])
def register_user(request):
    username = request.data.get('username')
    password = request.data.get('password')
    email = request.data.get('email')
    first_name = request.data.get('first_name')
    last_name = request.data.get('last_name')
    middle_initial = request.data.get('middle_initial')

    if not username or not password or not email :
        return JsonResponse({"message":"username or password or email required"},status=status.HTTP_400_BAD_REQUEST)
    try:
       

        data = {"username":username,"password":password, "email":email, "first_name":first_name, "last_name": last_name, "middle_initial":middle_initial}

        # Encrypt data with Fernet
        encrypted_data = f.encrypt(json.dumps(data).encode())


        # Send the encrypted user data to Project 2
        response = requests.post(f"{PROJECT2_URL}/api/register/", json={"data":encrypted_data.decode()})

        if response.status_code==status.HTTP_201_CREATED:

            return JsonResponse({'message':'User Registered','status':response.status_code},status=status.HTTP_201_CREATED)
        else:
            logger.error("Failed to register user in project 2 with status code :%s and response: %s",response.status_code,response.text)
            return JsonResponse({'message':'Server error try again later','status':response.status_code},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    except Exception as e:
        logger.error("Error during user registration in project 1", exc_info=True)
        return JsonResponse({'message':'username already exists'},status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
def login_user(request):
    username = request.data.get('username')
    password = request.data.get('password')

    if not username or not password:
        return JsonResponse({"message": "username or password required"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        # Prepare data for encryption
        data = {"username": username, "password": password}

        # Encrypt data with Fernet
        encrypted_data = f.encrypt(json.dumps(data).encode())
        logger.debug(f"Sending encrypted data: {encrypted_data.decode()}")

        # Send the encrypted user data to Project 2
        response = requests.post(f"{PROJECT2_URL}/api/login/", json={"data": encrypted_data.decode()})

        if response.status_code == status.HTTP_200_OK:
            # Pass back the success response from Project2
            response_data = response.json()
            return JsonResponse({
                'access': response_data.get('access'),
                'refresh': response_data.get('refresh'),
                'message': response_data.get('message'),
                'status': response.status_code,
                'user_id':response_data.get('user_id'),
                'username':response_data.get('username'),
                'bank_account': response_data.get('bank_account'),
            }, status=status.HTTP_200_OK)
        else:
            logger.error(f"Login failed with status code: {response.status_code}, and response text: {response.text}")
            return JsonResponse({'message': 'Invalid username or password', 'status': response.status_code},
                                status=response.status_code)
    except Exception as e:
        logger.error("Login in project 1 failed", exc_info=True)
        return JsonResponse({'message': 'Server error. Please try again later.'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    



@api_view(['POST'])
@authentication_classes([])
def logout_user(request):
    try:
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            logger.error("Refresh token not found in request body")
            return JsonResponse({"message": "Refresh token is required"}, status=status.HTTP_400_BAD_REQUEST)

        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            logger.error("Authorization header is missing or invalid")
            return JsonResponse({"message": "Authorization header is missing or invalid"}, status=status.HTTP_401_UNAUTHORIZED)
        
        access_token = auth_header.split(' ')[1]

        response = requests.post(
           f"{PROJECT2_URL}/api/logout/",
            headers={"Authorization": f"Bearer {access_token}"},
            json={"refresh": refresh_token},
        )
        logger.info(f"Response from Project 2: {response.status_code}, {response.text}")

        if response.status_code != 205 and response.status_code != 400:
            logger.error(f"Failed to logout user in Project2: {response.status_code}, {response.text}")
            return JsonResponse({"message": "Failed to logout on Project2"}, status=status.HTTP_400_BAD_REQUEST)

        return JsonResponse({"message": "Logout successfully"}, status=status.HTTP_205_RESET_CONTENT)

    except Exception as e:
        logger.error("Error during logout user in Project1", exc_info=True)
        return JsonResponse({"message": "Failed to logout"}, status=status.HTTP_400_BAD_REQUEST)
    


@api_view(['POST'])
@permission_classes([AllowAny])
def make_transfer(request):
    try:
        receiver_username = request.data.get('receiver_username')
        amount = request.data.get('amount')
        receiver_account_number = request.data.get('receiver_account_number')


        if not receiver_username or not amount or not receiver_account_number:
            return JsonResponse({"message":"receiver_username or amount or receiver account number required"},status=status.HTTP_400_BAD_REQUEST)
        try:
            amount = float(amount)
        except:
            return JsonResponse({"message":"Invalid amount"},status=status.HTTP_400_BAD_REQUEST)
        if amount <=0:
            return JsonResponse({"message":"Amount must be greater than zero"},status=status.HTTP_400_BAD_REQUEST)
        try:
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                 logger.error("Authorization header is missing or invalid")
                 return JsonResponse({"message": "Authorization header is missing or invalid"}, status=status.HTTP_401_UNAUTHORIZED)
            access_token = auth_header.split(' ')[1]
            
            sender_username = request.data.get('sender_username') #Extract user from the data

            # Data for transaction
            data = {
                "sender_username":sender_username,
                "receiver_username":receiver_username,
                "amount":amount,
                "receiver_account_number":receiver_account_number
            }

            encrypted_data = f.encrypt(json.dumps(data).encode())
            # Send transaction data to Project 2
            headers = {
                'Authorization':f"Bearer {access_token}",
                'Content-Type': 'application/json'
            }
            response = requests.post(f"{PROJECT2_URL}/api/transfer/", headers=headers, json={"data":encrypted_data.decode()})
            if response.status_code == status.HTTP_200_OK:
                return JsonResponse({'message':'Transfer successfull','status':response.status_code},status=status.HTTP_200_OK)
            else:
                logger.error("Failed to make transfer with status code :%s and response: %s",response.status_code,response.text)
                return JsonResponse({'message':'Transfer failed','status':response.status_code},status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
        except Exception as e:
            logger.error("Error in make_transfer in project1", exc_info=True)
            return JsonResponse({"message":"Failed to make transaction try again later"},status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        logger.error("Error in make_transfer in project1", exc_info=True)
        return JsonResponse({"message":"Failed to make transaction try again later"},status=status.HTTP_400_BAD_REQUEST)

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


def register_page(request):
    return render(request, 'register.html')

def login_page(request):
    return render(request, 'login.html')

@api_view(['GET'])
@authentication_classes([])
def home_page(request):
    return render(request,'home.html')

@api_view(['GET'])
@authentication_classes([])
def transfer_page(request):
    return render(request, 'transfer.html')

@api_view(['GET'])
@authentication_classes([])
def transaction_page(request):
    return render(request, "transactions.html")

@api_view(['GET'])
@authentication_classes([])
def user_profile(request):
    return render(request, 'profile.html')

@api_view(['GET'])
@authentication_classes([])
def welcome_page(request):
    return render(request, 'welcome.html')

