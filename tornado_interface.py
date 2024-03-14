# create tornado web server
import tornado
import tornado.web
import json
import backend
from http import HTTPStatus
import hashlib
import logging
from io import BytesIO
import model
logger = logging.getLogger(__name__)

class BaseHandler(tornado.web.RequestHandler):
    blacklisted_tokens = set()
    def get_current_user(self):
        if self.get_cookie("username") in BaseHandler.blacklisted_tokens:
            return None
        return self.get_signed_cookie("username").decode('utf-8')
    
class LoginHandler(BaseHandler):    
    def post(self):
        data = json.loads(self.request.body.decode('utf-8'))
        username = data.get('username', None)
        password = data.get('password', None)
        if username is None or password is None:
            self.write({"msg": "Missing username or password"})
            self.set_status(HTTPStatus.BAD_REQUEST)
            return
        # hash password with sha256
        password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        user = model.User(username=username, password=password)
        with backend.get_session() as session:
            try:
                backend.login(user, session)
                self.write({"msg": "Logined successfully"})
                self.set_signed_cookie("username", username)
            except RuntimeError as ex:
                logger.error(ex)
                self.set_status(HTTPStatus.UNAUTHORIZED)
                self.write({"msg": "Bad username or password"})

class LogoutHandler(BaseHandler):
    @tornado.web.authenticated
    def delete(self):
        BaseHandler.blacklisted_tokens.add(self.get_cookie("username"))
        self.clear_cookie("username")
        self.write({"msg": "Successfully logged out"})


class UserHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        with backend.get_session() as session:
            try:
                backend.check_admin(model.User(username=self.get_current_user()), session)
            except RuntimeError:
                self.write({"msg": "You are not admin"})
                self.set_status(HTTPStatus.FORBIDDEN)
                return
            users = backend.list_users(session)
            self.write(json.dumps([user.to_dict() for user in users]))

    @tornado.web.authenticated
    def post(self):
        with backend.get_session() as session:
            try:
                backend.check_admin(model.User(username=self.get_current_user()), session)
            except RuntimeError:
                self.write({"msg": "You are not admin"})
                self.set_status(HTTPStatus.FORBIDDEN)
                return
            data = json.loads(self.request.body.decode('utf-8'))
            username = data.get('username', None)
            password = data.get('password', None)
            is_admin = data.get('is_admin', 0)
            if username is None or password is None:
                self.write({"msg": "Missing username or password"})
                self.set_status(HTTPStatus.BAD_REQUEST)
                return
            # hash password with sha256
            password = hashlib.sha256(password.encode('utf-8')).hexdigest()
            user = model.User(username=username, password=password, is_admin=is_admin)
            if backend.check_user_exists(user, session):
                self.write({"msg": "User already exists"})
                self.set_status(HTTPStatus.BAD_REQUEST)
                return
            backend.add_user(user, session)
            self.write({"msg": "User added"})

    @tornado.web.authenticated
    def delete(self):
        with backend.get_session() as session:
            try:
                backend.check_admin(model.User(username=self.get_current_user()), session)
            except RuntimeError:
                self.write({"msg": "You are not admin"})
                self.set_status(HTTPStatus.FORBIDDEN)
                return
            data = json.loads(self.request.body.decode('utf-8'))
            username = data.get('username', None)
            if username is None:
                self.write({"msg": "Missing username"})
                self.set_status(HTTPStatus.BAD_REQUEST)
                return
            user = model.User(username=username)
            if not backend.check_user_exists(user, session):
                self.write({"msg": "User does not exist"})
                self.set_status(HTTPStatus.BAD_REQUEST)
                return
            backend.remove_user(user, session)
            self.write({"msg": "User removed"})

class PacketHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        with backend.get_session() as session:
            username = self.get_current_user()
            size_range = self.get_argument('size_range', '0,1000000000')
            time_range = self.get_argument('time_range', '0,2000000000')
            user = model.User(username=username)
            try:
                backend.check_admin(user, session)
                packets = backend.query_packets_admin(size_range, time_range, session)
            except RuntimeError:
                packets = backend.query_packets_user(user, size_range, time_range, session)
            packets = [packet.to_dict() for packet in packets]
            self.write(json.dumps(packets))
        
    @tornado.web.authenticated
    def post(self):
        size = self.get_argument('size', None)
        time = self.get_argument('time', None)
        username = self.get_current_user()
        if size is None or time is None:
            self.write({"msg": "Missing size or time"})
            self.set_status(HTTPStatus.BAD_REQUEST)
            return
        with backend.get_session() as session:
            packet = model.Packet(size=size, time=time, username=username)
            backend.add_packet(packet, session)
        self.write({"msg": "Packet added"})

class GetTotalHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        with backend.get_session() as session:
            total_packets, total_size = backend.get_total(session)
            self.write({"total_packets": total_packets, "total_size": total_size})


class GetAverageHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        with backend.get_session() as session:
            average = backend.get_average(session)
            self.write({"average": average})

class GetThroughputHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        with backend.get_session() as session:
            # save plt to file
            plt = backend.get_throughput(session)
            # get figure and set it's size to 12inch x 8inch
            fig = plt.gcf()
            fig.set_size_inches(12, 8)
            
            buf = BytesIO()
            plt.savefig(buf, format='png')
            buf.seek(0)
            content = buf.read()
            # set content type to image/png
            self.set_header('Content-Type', 'image/png')
            self.write(content)

class GetPacketPlotHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        with backend.get_session() as session:
            # save plt to file
            plt = backend.get_packet_plot(session)
            # get figure and set it's size to 12inch x 8inch
            fig = plt.gcf()
            fig.set_size_inches(12, 8)
            
            buf = BytesIO()
            plt.savefig(buf, format='png')
            buf.seek(0)
            content = buf.read()
            # set content type to image/png
            self.set_header('Content-Type', 'image/png')
            self.write(content)

def main():
    application = tornado.web.Application([
        (r"/login", LoginHandler),
        (r"/logout", LogoutHandler),
        (r"/user", UserHandler),
        (r"/packet", PacketHandler),
        (r"/packet/total", GetTotalHandler),
        (r"/packet/average", GetAverageHandler),
        (r"/packet/throughput", GetThroughputHandler),
        (r"/packet/plot", GetPacketPlotHandler),
    ], cookie_secret="__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__")
    # run server
    application.listen(5001)
    tornado.ioloop.IOLoop.current().start()

if __name__ == "__main__":
    main()