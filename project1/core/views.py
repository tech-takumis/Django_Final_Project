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
    if not username or not password or not email:
        return JsonResponse({"message":"username or password or email required"},status=status.HTTP_400_BAD_REQUEST)
    try:
        user = User.objects.create_user(username=username, password=password,email=email)

        data = {"username":username,"password":password, "email":email}

        # Encrypt data with Fernet
        encrypted_data = f.encrypt(json.dumps(data).encode())


        # Send the encrypted user data to Project 2
        response = requests.post(f"{PROJECT2_URL}/api/register/", json={"data":encrypted_data.decode()})

        if response.status_code==status.HTTP_201_CREATED:

            return JsonResponse({'message':'User Registered','status':response.status_code},status=status.HTTP_201_CREATED)
        else:

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
@permission_classes([IsAuthenticated])
def make_transfer(request):
    try:
        receiver_username = request.data.get('receiver_username')
        amount = request.data.get('amount')
        
        if not receiver_username or not amount:
            return JsonResponse({"message":"receiver_username or amount required"},status=status.HTTP_400_BAD_REQUEST)
        try:
            amount = float(amount)
        except:
            return JsonResponse({"message":"Invalid amount"},status=status.HTTP_400_BAD_REQUEST)
        if amount <=0:
            return JsonResponse({"message":"Amount must be greater than zero"},status=status.HTTP_400_BAD_REQUEST)
        try:
            user = request.user
        
            # Data for transaction
            data = {
                "sender_username":user.username,
                "receiver_username":receiver_username,
                "amount":amount
            }

            encrypted_data = f.encrypt(json.dumps(data).encode())
            # Send transaction data to Project 2
            headers = {
                'Authorization':f"Bearer {request.META.get('HTTP_AUTHORIZATION').split()[1]}",
                'Content-Type': 'application/json'
            }
            response = requests.post(f"{PROJECT2_URL}/api/transfer/", headers=headers, json={"data":encrypted_data.decode()})
            if response.status_code == status.HTTP_200_OK:
                return JsonResponse({'message':'transfer successfull','status':response.status_code},status=status.HTTP_200_OK)
            else:
                logger.error("Failed to make transfer with status code :%s and response: %s",response.status_code,response.text)
                return JsonResponse({'message':'Transfer failed','status':response.status_code},status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
        except User.DoesNotExist:
                return JsonResponse({"message":"receiver does not exists"},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error("Error in make_transfer in project1", exc_info=True)
            return JsonResponse({"message":"Failed to make transaction try again later"},status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        logger.error("Error in make_transfer in project1", exc_info=True)
        return JsonResponse({"message":"Failed to make transaction try again later"},status=status.HTTP_400_BAD_REQUEST)
        

def register_page(request):
    return render(request, 'register.html')

def login_page(request):
    return render(request, 'login.html')

def transfer_page(request):
    return render(request, 'transfer.html')

def transaction_page(request):
    access_token = request.COOKIES.get('access_token')
    logger.debug(f"Access Token from Cookies: {access_token}")

    if not access_token:
        return JsonResponse({'error': 'Access token not found in cookies'}, status=400)
    
    try:
        response = requests.get(
            f"{PROJECT2_URL}/api/transactions/",
            headers={'Authorization': f'Bearer {access_token}'}
        )
        response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)

        response_data = response.json()
       
        encrypted_data = response_data.get('data')

        if not encrypted_data:
            return JsonResponse({'error': "Encrypted data not found in response"}, status=400)

        decrypted_data = json.loads(f.decrypt(encrypted_data.encode()).decode())

        response_dict = {
                'data': decrypted_data,
            }

        return JsonResponse(response_dict, safe=False)

    except requests.exceptions.RequestException as e:
        logger.error("Error making request to Project2: %s", e, exc_info=True)
        return JsonResponse({'error': f"Failed to fetch data from Project2: {e}"}, status=500)
    except json.JSONDecodeError as e:
        logger.error("Error decoding JSON response: %s", e, exc_info=True)
        return JsonResponse({'error': "Error decoding JSON"}, status=500)
    except Exception as e:
        logger.error("Error in transaction page: %s", e, exc_info=True)
        return JsonResponse({'error': "Error decrypting data or other processing error"}, status=500)
    


def user_page(request):
    access_token = request.COOKIES.get('access_token')
    response = requests.get(f"{PROJECT2_URL}/api/users/", headers={'Authorization': f'Bearer {access_token}'})
    if response.status_code == 200:
           try:
                decrypted_data = json.loads(f.decrypt(json.loads(response.content)['data'].encode()).decode())
                return render(request, 'users.html', {'data': decrypted_data, 'next':json.loads(response.content).get('next'), 'previous': json.loads(response.content).get('previous')})
           except Exception as e:
                logger.error("Error in user page", exc_info=True)
                return render(request, 'users.html', {'message': "Error decrypting data"})
    else:
        logger.error("Error in user page with status code :%s and response: %s",response.status_code,response.text)
        return render(request, 'users.html', {'message': f"Failed to fetch data with status {response.status_code}"})


def account_page(request):
    access_token = request.COOKIES.get('access_token')
    response = requests.get(f"{PROJECT2_URL}/api/accounts/", headers={'Authorization': f'Bearer {access_token}'})
    if response.status_code == 200:
        try:
            decrypted_data = json.loads(f.decrypt(json.loads(response.content)['data'].encode()).decode())
            return render(request, 'accounts.html', {'data': decrypted_data, 'next':json.loads(response.content).get('next'), 'previous': json.loads(response.content).get('previous')})
        except Exception as e:
             logger.error("Error in account page", exc_info=True)
             return render(request, 'accounts.html', {'message': "Error decrypting data"})
    else:
        logger.error("Error in account page with status code :%s and response: %s",response.status_code,response.text)
        return render(request, 'accounts.html', {'message': f"Failed to fetch data with status {response.status_code}"})