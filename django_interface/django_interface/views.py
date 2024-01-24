import backend
import hashlib
from . import auth_with_jwt
from django.http import HttpResponse
from http import HTTPStatus
import logging
from django.views.decorators.csrf import csrf_exempt
import json
from io import BytesIO

logger = logging.getLogger("django_interface")

def get_conn():
    return backend.connect_db()

@csrf_exempt
def login_view(request):
    if request.method != 'POST':
        return HttpResponse(status=HTTPStatus.METHOD_NOT_ALLOWED)
    data = json.loads(request.read())
    username = data.get('username')
    password = data.get('password')
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

    try:
        backend.login(username, hashed_password, conn=get_conn())
        token = auth_with_jwt.get_token(username)

        return HttpResponse(json.dumps({'access_token': token}))
    except RuntimeError as ex:
        logger.error(ex)
        return HttpResponse(json.dumps({"msg": "Bad username or password"}), status=HTTPStatus.UNAUTHORIZED)
    
@csrf_exempt
def logout_view(request):
    if request.method != 'DELETE':
        return HttpResponse(status=HTTPStatus.METHOD_NOT_ALLOWED)
    if 'HTTP_AUTHORIZATION' not in request.META:
        return HttpResponse(status=HTTPStatus.UNAUTHORIZED)
    token = request.META['HTTP_AUTHORIZATION'].split()[1]
    if not auth_with_jwt.check_token_blacklisted(token):
        return HttpResponse(json.dumps({"msg": "Token already blacklisted"}), status=HTTPStatus.BAD_REQUEST)
    auth_with_jwt.blacklist_token(token)
    return HttpResponse(json.dumps({"msg": "Successfully logged out"}), status=HTTPStatus.OK)

@csrf_exempt
def add_user(request):
    if request.method != 'POST':
        return HttpResponse(status=HTTPStatus.METHOD_NOT_ALLOWED)
    if 'HTTP_AUTHORIZATION' not in request.META:
        return HttpResponse(status=HTTPStatus.UNAUTHORIZED)
    token = request.META['HTTP_AUTHORIZATION'].split()[1]
    if not auth_with_jwt.check_token_blacklisted(token):
        return HttpResponse(json.dumps({"msg": "Token already blacklisted"}), status=HTTPStatus.BAD_REQUEST)
    conn = get_conn()
    try: 
        user = auth_with_jwt.get_user(request)
    except RuntimeError as ex:
        return HttpResponse(json.dumps({"msg": str(ex)}), status=HTTPStatus.UNAUTHORIZED)
    try:
        backend.check_admin(user, conn)
    except RuntimeError:
        return HttpResponse(json.dumps({"msg": "You are not admin"}), status=HTTPStatus.FORBIDDEN)
    data = json.loads(request.read())
    username = data.get('username')
    password = data.get('password')
    if username is None or password is None:
        return HttpResponse(json.dumps({"msg": "Missing username or password"}), status=HTTPStatus.BAD_REQUEST)
    if backend.check_user_exists(username, conn):
        return HttpResponse(json.dumps({"msg": "User already exists"}), status=HTTPStatus.BAD_REQUEST)
    # hash password with sha256
    password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    backend.add_user(username, password, conn)
    return HttpResponse(json.dumps({"msg": "User added"}), status=HTTPStatus.OK)

@csrf_exempt
def remove_user(request):
    if request.method != 'DELETE':
        return HttpResponse(status=HTTPStatus.METHOD_NOT_ALLOWED)
    if 'HTTP_AUTHORIZATION' not in request.META:
        return HttpResponse(status=HTTPStatus.UNAUTHORIZED)
    conn = get_conn()
    try: 
        user = auth_with_jwt.get_user(request)
    except RuntimeError as ex:
        return HttpResponse(json.dumps({"msg": str(ex)}), status=HTTPStatus.UNAUTHORIZED)
    try:
        backend.check_admin(user, conn)
    except RuntimeError:
        return HttpResponse(json.dumps({"msg": "You are not admin"}), status=HTTPStatus.FORBIDDEN)
    data = json.loads(request.read())
    username = data.get('username')
    if username is None:
        return HttpResponse(json.dumps({"msg": "Missing username"}), status=HTTPStatus.BAD_REQUEST)
    if not backend.check_user_exists(username, conn):
        return HttpResponse(json.dumps({"msg": "User does not exist"}), status=HTTPStatus.BAD_REQUEST)
    backend.remove_user(username, conn)
    return HttpResponse(json.dumps({"msg": "User removed"}), status=HTTPStatus.OK)

def list_users(request):
    if request.method != 'GET':
        return HttpResponse(status=HTTPStatus.METHOD_NOT_ALLOWED)
    if 'HTTP_AUTHORIZATION' not in request.META:
        return HttpResponse(status=HTTPStatus.UNAUTHORIZED)
    conn = get_conn()
    try: 
        user = auth_with_jwt.get_user(request)
    except RuntimeError as ex:
        return HttpResponse(json.dumps({"msg": str(ex)}), status=HTTPStatus.UNAUTHORIZED)
    try:
        backend.check_admin(user, conn)
    except RuntimeError:
        return HttpResponse(json.dumps({"msg": "You are not admin"}), status=HTTPStatus.FORBIDDEN)
    users = backend.list_users(conn)
    users = [{"username": user[0], "password": user[1], "is_admin": user[2]} for user in users]
    return HttpResponse(json.dumps(users), status=HTTPStatus.OK)

@csrf_exempt
def add_packet(request):
    if request.method != 'POST':
        return HttpResponse(status=HTTPStatus.METHOD_NOT_ALLOWED)
    if 'HTTP_AUTHORIZATION' not in request.META:
        return HttpResponse(status=HTTPStatus.UNAUTHORIZED)
    conn = get_conn()
    try: 
        user = auth_with_jwt.get_user(request)
    except RuntimeError as ex:
        return HttpResponse(json.dumps({"msg": str(ex)}), status=HTTPStatus.UNAUTHORIZED)
    data = json.loads(request.read())
    size = data.get('size')
    time = data.get('time')
    if size is None or time is None:
        return HttpResponse(json.dumps({"msg": "Missing size or time"}), status=HTTPStatus.BAD_REQUEST)
    backend.add_packet(size, time, user, conn)
    return HttpResponse(json.dumps({"msg": "Packet added"}), status=HTTPStatus.OK)

@csrf_exempt
def query_packets(request):
    if request.method != 'GET':
        return HttpResponse(status=HTTPStatus.METHOD_NOT_ALLOWED)
    if 'HTTP_AUTHORIZATION' not in request.META:
        return HttpResponse(status=HTTPStatus.UNAUTHORIZED)
    conn = get_conn()
    try: 
        username = auth_with_jwt.get_user(request)
    except RuntimeError as ex:
        return HttpResponse(json.dumps({"msg": str(ex)}), status=HTTPStatus.UNAUTHORIZED)
    size_range = request.GET.get('size_range', "0,10000000000")
    time_range = request.GET.get('time_range', "0,10000000000")
    try:
        backend.check_admin(username, conn)
        packets = backend.query_packets_admin(size_range, time_range, conn)
    except RuntimeError:
        packets = backend.query_packets_user(username, size_range, time_range, conn)
    packets = [{"packet_id": packet[0], "packet_size": packet[1], "packet_time": packet[2], "user": packet[3]} for packet in packets]
    return HttpResponse(json.dumps(packets), status=HTTPStatus.OK)

def get_total(request):
    if request.method != 'GET':
        return HttpResponse(status=HTTPStatus.METHOD_NOT_ALLOWED)
    if 'HTTP_AUTHORIZATION' not in request.META:
        return HttpResponse(status=HTTPStatus.UNAUTHORIZED)
    conn = get_conn()
    try: 
        auth_with_jwt.get_user(request)
    except RuntimeError as ex:
        return HttpResponse(json.dumps({"msg": str(ex)}), status=HTTPStatus.UNAUTHORIZED)
    total_packets, total_size = backend.get_total(conn)
    return HttpResponse(json.dumps({"total_packets": total_packets, "total_size": total_size}), status=HTTPStatus.OK)

def get_average(request):
    if request.method != 'GET':
        return HttpResponse(status=HTTPStatus.METHOD_NOT_ALLOWED)
    if 'HTTP_AUTHORIZATION' not in request.META:
        return HttpResponse(status=HTTPStatus.UNAUTHORIZED)
    conn = get_conn()
    try: 
        auth_with_jwt.get_user(request)
    except RuntimeError as ex:
        return HttpResponse(json.dumps({"msg": str(ex)}), status=HTTPStatus.UNAUTHORIZED)
    average_size = backend.get_average(conn)
    return HttpResponse(json.dumps({"average_size": average_size}), status=HTTPStatus.OK)

def get_throughput(request):
    if request.method != 'GET':
        return HttpResponse(status=HTTPStatus.METHOD_NOT_ALLOWED)
    if 'HTTP_AUTHORIZATION' not in request.META:
        return HttpResponse(status=HTTPStatus.UNAUTHORIZED)
    conn = get_conn()
    try: 
        auth_with_jwt.get_user(request)
    except RuntimeError as ex:
        return HttpResponse(json.dumps({"msg": str(ex)}), status=HTTPStatus.UNAUTHORIZED)
    # save plt to file
    plt = backend.get_throughput(conn)
    # get figure and set it's size to 12inch x 8inch
    fig = plt.gcf()
    fig.set_size_inches(12, 8)
    buf = BytesIO() 
    plt.savefig(buf, format="png")
    buf.seek(0)
    # send file to client
    return HttpResponse(buf, content_type='image/png')

def get_packet_plot(request):
    if request.method != 'GET':
        return HttpResponse(status=HTTPStatus.METHOD_NOT_ALLOWED)
    if 'HTTP_AUTHORIZATION' not in request.META:
        return HttpResponse(status=HTTPStatus.UNAUTHORIZED)
    conn = get_conn()
    try: 
        auth_with_jwt.get_user(request)
    except RuntimeError as ex:
        return HttpResponse(json.dumps({"msg": str(ex)}), status=HTTPStatus.UNAUTHORIZED)
    # save plt to file
    plt = backend.get_packet_plot(conn)
    # get figure and set it's size to 12inch x 8inch
    fig = plt.gcf()
    fig.set_size_inches(12, 8)
    buf = BytesIO() 
    plt.savefig(buf, format="png")
    buf.seek(0)
    # send file to client
    return HttpResponse(buf, content_type='image/png')

