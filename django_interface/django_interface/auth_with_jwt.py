import jwt
import datetime
import model

SECRET_KEY = 'test'  # replace with your secret key

def get_token(username):
    payload = {
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token

def check_token_blacklisted(token):
    return token not in check_token_blacklisted.blacklist
check_token_blacklisted.blacklist = set()

def blacklist_token(token):
    check_token_blacklisted.blacklist.add(token)

def get_user(request: 'django.http.request.HttpRequest'):
    # get Authorization header from django request
    token = request.META.get('HTTP_AUTHORIZATION').split()[1]
    if token in check_token_blacklisted.blacklist:
        raise RuntimeError('Token blacklisted')
    payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    # check expiration time
    exp = payload.get('exp')
    if datetime.datetime.utcnow() > datetime.datetime.fromtimestamp(exp):
        raise RuntimeError('Token expired')
    username = payload.get('username')
    return model.User(username=username)