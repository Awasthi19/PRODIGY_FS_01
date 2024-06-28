from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import User
import jwt
from django.contrib.auth.hashers import make_password, check_password
import datetime
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

class SignupView(APIView):
    permission_classes = []
    authentication_classes = []

    def post(self, request):

        try:
            email = request.data.get('email')
            password = request.data.get('password')

            if  not email or not password:
                return Response({'message': 'Please fill all the fields'}, status=status.HTTP_400_BAD_REQUEST)

            if User.objects.filter(email=email).exists():
                return Response({'message': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)

            hashed_password = make_password(password)
            user = User(email=email, password=hashed_password)
            user.save()

            return Response({'message': 'User created'}, status=status.HTTP_201_CREATED)
        except Exception as e:
            logger.error(f"Error in SignupView: {str(e)}", exc_info=True)
            return Response({'message': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class LoginView(APIView):
    permission_classes = []
    authentication_classes = []

    def post(self, request):
        print("Login view")
        email = request.data.get('email')
        password = request.data.get('password')
        print(email)

        if not email or not password:
            return Response({'message': 'Email and password are required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        if not check_password(password, user.password):
            return Response({'message': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        now = datetime.datetime.now(datetime.timezone.utc)
        expiration = now + datetime.timedelta(minutes=60)

        payload = {
            'id': user.id,
            'email': user.email,
            'exp': expiration,
            'iat': now
        }

        try:
            token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
        except Exception as e:
            return Response({'message': f'Error encoding token: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        response = Response({'jwt': token}, status=status.HTTP_200_OK)
        response.set_cookie(key='jwt', value=token, httponly=True)
        
        return response
        

class ProfileView(APIView):
    permission_classes = []
    authentication_classes = []

    def get(self, request):
        token = request.headers.get('Authorization', None)
        if not token or not token.startswith('Bearer '):
            return Response({'error': 'Not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

        token = token.split(' ')[1]
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({'error': 'Token expired'}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError as e:
            logger.error(f"Invalid token error: {str(e)}", exc_info=True)
            return Response({'error': 'Invalid token'}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            user = User.objects.get(id=payload['id'])
            response_data = {
                'id': user.id,
                'email': user.email,
            }
            return Response(response_data, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

class LogoutView(APIView):
    permission_classes = []
    authentication_classes = []

    def post(self, request):
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            'message': 'logged out'
        }

