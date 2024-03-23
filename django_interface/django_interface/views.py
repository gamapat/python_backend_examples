import backend
import hashlib
from . import auth_with_jwt
from django.http import HttpResponse
from django.views import View
from http import HTTPStatus
import logging
from django.views.decorators.csrf import csrf_exempt
import json
from io import BytesIO
import model
from django.utils.decorators import method_decorator

logger = logging.getLogger("django_interface")

def get_session():
    return backend.get_session()

def check_authorization(request):
    if 'HTTP_AUTHORIZATION' not in request.META:
        return HttpResponse(status=HTTPStatus.UNAUTHORIZED)
    token = request.META['HTTP_AUTHORIZATION'].split()[1]
    if not auth_with_jwt.check_token_blacklisted(token):
        return HttpResponse(json.dumps({"msg": "Token already blacklisted"}), status=HTTPStatus.BAD_REQUEST)
    return None

@method_decorator(csrf_exempt, name='dispatch')
class LoginView(View):
    def post(self, request):
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')
        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        with get_session() as session:
            try:
                user = model.User(username=username, password=hashed_password)
                backend.login(user, session)
                token = auth_with_jwt.get_token(username)

                return HttpResponse(json.dumps({'access_token': token}))
            except RuntimeError as ex:
                logger.error(ex)
                return HttpResponse(json.dumps({"msg": "Bad username or password"}), status=HTTPStatus.UNAUTHORIZED)
            
    def delete(self, request):
        res = check_authorization(request)
        if res is not None:
            return res
        token = request.META['HTTP_AUTHORIZATION'].split()[1]
        auth_with_jwt.blacklist_token(token)
        return HttpResponse(json.dumps({"msg": "Successfully logged out"}), status=HTTPStatus.OK)
    
@method_decorator(csrf_exempt, name='dispatch')
class User(View):
    def get(self, request):
        res = check_authorization(request)
        if res is not None:
            return res
        with get_session() as session:
            try: 
                user = auth_with_jwt.get_user(request)
            except RuntimeError as ex:
                return HttpResponse(json.dumps({"msg": str(ex)}), status=HTTPStatus.UNAUTHORIZED)
            try:
                backend.check_admin(user, session)
            except RuntimeError:
                return HttpResponse(json.dumps({"msg": "You are not admin"}), status=HTTPStatus.FORBIDDEN)
            users = backend.list_users(session)
            users = [user.to_dict() for user in users]
            return HttpResponse(json.dumps(users), status=HTTPStatus.OK)

    def post(self, request):
        res = check_authorization(request)
        if res is not None:
            return res
        with get_session() as session:
            try: 
                login_user = auth_with_jwt.get_user(request)
            except RuntimeError as ex:
                return HttpResponse(json.dumps({"msg": str(ex)}), status=HTTPStatus.UNAUTHORIZED)
            try:
                backend.check_admin(login_user, session)
            except RuntimeError:
                return HttpResponse(json.dumps({"msg": "You are not admin"}), status=HTTPStatus.FORBIDDEN)
            data = json.loads(request.body)
            username = data.get('username')
            password = data.get('password')
            if username is None or password is None:
                return HttpResponse(json.dumps({"msg": "Missing username or password"}), status=HTTPStatus.BAD_REQUEST)
            # hash password with sha256
            password = hashlib.sha256(password.encode('utf-8')).hexdigest()
            user = model.User(username=username, password=password)
            if backend.check_user_exists(user, session):
                return HttpResponse(json.dumps({"msg": "User already exists"}), status=HTTPStatus.BAD_REQUEST)
            backend.add_user(user, session)
            return HttpResponse(json.dumps({"msg": "User added"}), status=HTTPStatus.OK)

    def delete(self, request):
        res = check_authorization(request)
        if res is not None:
            return res
        with get_session() as session:
            try:
                login_user = auth_with_jwt.get_user(request)
            except RuntimeError as ex:
                return HttpResponse(json.dumps({"msg": str(ex)}), status=HTTPStatus.UNAUTHORIZED)
            try:
                backend.check_admin(login_user, session)
            except RuntimeError:
                return HttpResponse(json.dumps({"msg": "You are not admin"}), status=HTTPStatus.FORBIDDEN)
            data = json.loads(request.body)
            username = data.get('username')
            if username is None:
                return HttpResponse(json.dumps({"msg": "Missing username"}), status=HTTPStatus.BAD_REQUEST)
            user = model.User(username=username)
            if not backend.check_user_exists(user, session):
                return HttpResponse(json.dumps({"msg": "User does not exist"}), status=HTTPStatus.BAD_REQUEST)
            backend.remove_user(user, session)
            return HttpResponse(json.dumps({"msg": "User removed"}), status=HTTPStatus.OK)

@method_decorator(csrf_exempt, name='dispatch')
class Packet(View):
    def post(self, request):
        res = check_authorization(request)
        if res is not None:
            return res
        with get_session() as session:
            try: 
                login_user = auth_with_jwt.get_user(request)
            except RuntimeError as ex:
                return HttpResponse(json.dumps({"msg": str(ex)}), status=HTTPStatus.UNAUTHORIZED)
            data = json.loads(request.body)
            size = data.get('size')
            time = data.get('time')
            if size is None or time is None:
                return HttpResponse(json.dumps({"msg": "Missing size or time"}), status=HTTPStatus.BAD_REQUEST)
            packet = model.Packet(size=size, time=time, user=login_user)
            backend.add_packet(packet, session)
            return HttpResponse(json.dumps({"msg": "Packet added"}), status=HTTPStatus.OK)

    def get(self, request):
        res = check_authorization(request)
        if res is not None:
            return res
        with get_session() as session:
            try: 
                login_user = auth_with_jwt.get_user(request)
            except RuntimeError as ex:
                return HttpResponse(json.dumps({"msg": str(ex)}), status=HTTPStatus.UNAUTHORIZED)
            size_range = request.GET.get('size_range', "0,10000000000")
            time_range = request.GET.get('time_range', "0,10000000000")
            try:
                backend.check_admin(login_user, session)
                packets = backend.query_packets_admin(size_range, time_range, session)
            except RuntimeError:
                packets = backend.query_packets_user(login_user, size_range, time_range, session)
            packets = [packet.to_dict() for packet in packets]
            return HttpResponse(json.dumps(packets), status=HTTPStatus.OK)

class Total(View):
    def get(self, request):
        res = check_authorization(request)
        if res is not None:
            return res
        with get_session() as session:
            try: 
                auth_with_jwt.get_user(request)
            except RuntimeError as ex:
                return HttpResponse(json.dumps({"msg": str(ex)}), status=HTTPStatus.UNAUTHORIZED)
            total_packets, total_size = backend.get_total(session)
            return HttpResponse(json.dumps({"total_packets": total_packets, "total_size": total_size}), status=HTTPStatus.OK)
        
class Average(View):
    def get(self, request):
        res = check_authorization(request)
        if res is not None:
            return res
        with get_session() as session:
            try: 
                auth_with_jwt.get_user(request)
            except RuntimeError as ex:
                return HttpResponse(json.dumps({"msg": str(ex)}), status=HTTPStatus.UNAUTHORIZED)
            average_size = backend.get_average(session)
            return HttpResponse(json.dumps({"average_size": average_size}), status=HTTPStatus.OK)
        
class Throughput(View):
    def get(self, request):
        res = check_authorization(request)
        if res is not None:
            return res
        with get_session() as session:
            try: 
                auth_with_jwt.get_user(request)
            except RuntimeError as ex:
                return HttpResponse(json.dumps({"msg": str(ex)}), status=HTTPStatus.UNAUTHORIZED)
            # save plt to file
            plt = backend.get_throughput(session)
            # get figure and set it's size to 12inch x 8inch
            fig = plt.gcf()
            fig.set_size_inches(12, 8)
            buf = BytesIO() 
            plt.savefig(buf, format="png")
            buf.seek(0)
            # send file to client
            return HttpResponse(buf, content_type='image/png')

class PacketPlot(View):
    def get(self, request):
        res = check_authorization(request)
        if res is not None:
            return res
        with get_session() as session:
            try: 
                auth_with_jwt.get_user(request)
            except RuntimeError as ex:
                return HttpResponse(json.dumps({"msg": str(ex)}), status=HTTPStatus.UNAUTHORIZED)
            # save plt to file
            plt = backend.get_packet_plot(session)
            # get figure and set it's size to 12inch x 8inch
            fig = plt.gcf()
            fig.set_size_inches(12, 8)
            buf = BytesIO() 
            plt.savefig(buf, format="png")
            buf.seek(0)
            # send file to client
            return HttpResponse(buf, content_type='image/png')
