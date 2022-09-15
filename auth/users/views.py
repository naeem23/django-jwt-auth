from hashlib import algorithms_available
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response  
from rest_framework.views import APIView
import jwt, datetime

from .models import User
from .serializers import UserSerializer

class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class LoginView(APIView):
    def post(self, request):
        email = request.data['email']
        password = request.data['password']
        
        user = User.objects.filter(email=email).first()
        if user is None:
            raise AuthenticationFailed("Invalid user credentials!")
        if not user.check_password(password):
            raise AuthenticationFailed('Invalid user credentials!')

        payload = {
            'id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.utcnow()
        }

        token = jwt.encode(payload, 'mysecret', algorithm='HS256')

        response = Response()
        response.set_cookie(key='token', value=token, httponly=True)
        response.data = {
            'token': token
        }

        return response


class UserView(APIView):
    def get(self, request):
        token = request.COOKIES.get('token')
        if not token:
            raise AuthenticationFailed('Authentication failed!')

        try:
            payload = jwt.decode(token, 'mysecret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Authentication failed!')

        user = User.objects.filter(id=payload['id']).first()
        serializer = UserSerializer(user)
        return Response(serializer.data)


class LogoutView(APIView):
    def get(self, request):
        response = Response()
        response.delete_cookie('token')
        response.data = {
            'message': 'Logout success'
        }
        return response 