# create tornado web server
import tornado
import tornado.web
import json
import backend
from http import HTTPStatus
import hashlib
import logging
from io import BytesIO
import sys
logger = logging.getLogger(__name__)

class BaseHandler(tornado.web.RequestHandler):
    blacklisted_tokens = set()
    def get_current_user(self):
        if self.get_cookie("username") in BaseHandler.blacklisted_tokens:
            return None
        return self.get_signed_cookie("username").decode('utf-8')
    
class LoginHandler(BaseHandler):    
    def initialize(self, conn):
        self.conn = conn

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
        try:
            backend.login(username, password, self.conn)
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


class AddUserHandler(BaseHandler):
    def initialize(self, conn):
        self.conn = conn

    @tornado.web.authenticated
    def post(self):
        try:
            backend.check_admin(self.get_current_user(), self.conn)
        except RuntimeError:
            self.write({"msg": "You are not admin"})
            self.set_status(HTTPStatus.FORBIDDEN)
            return
        username = self.get_argument('username', None)
        password = self.get_argument('password', None)
        if username is None or password is None:
            self.write({"msg": "Missing username or password"})
            self.set_status(HTTPStatus.BAD_REQUEST)
            return
        if backend.check_user_exists(username, self.conn):
            self.write({"msg": "User already exists"})
            self.set_status(HTTPStatus.BAD_REQUEST)
            return
        # hash password with sha256
        password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        backend.add_user(username, password, self.conn)
        self.write({"msg": "User added"})

class RemoveUserHandler(BaseHandler):
    def initialize(self, conn):
        self.conn = conn

    @tornado.web.authenticated
    def delete(self):
        try:
            backend.check_admin(self.get_current_user(), self.conn)
        except RuntimeError:
            self.write({"msg": "You are not admin"})
            self.set_status(HTTPStatus.FORBIDDEN)
            return
        username = self.get_argument('username', None)
        if username is None:
            self.write({"msg": "Missing username"})
            self.set_status(HTTPStatus.BAD_REQUEST)
            return
        if not backend.check_user_exists(username, self.conn):
            self.write({"msg": "User does not exist"})
            self.set_status(HTTPStatus.BAD_REQUEST)
            return
        backend.remove_user(username, self.conn)
        self.write({"msg": "User removed"})

class ListUsersHandler(BaseHandler):
    def initialize(self, conn):
        self.conn = conn

    @tornado.web.authenticated
    def get(self):
        try:
            backend.check_admin(self.get_current_user(), self.conn)
        except RuntimeError:
            self.write({"msg": "You are not admin"})
            self.set_status(HTTPStatus.FORBIDDEN)
            return
        users = backend.list_users(self.conn)
        users = [{"username": user[0], "password": user[1], "is_admin": user[2]} for user in users]
        self.write(json.dumps(users))

class AddPacketHandler(BaseHandler):
    def initialize(self, conn):
        self.conn = conn

    @tornado.web.authenticated
    def post(self):
        size = self.get_argument('size', None)
        time = self.get_argument('time', None)
        username = self.get_current_user()
        if size is None or time is None:
            self.write({"msg": "Missing size or time"})
            self.set_status(HTTPStatus.BAD_REQUEST)
            return
        backend.add_packet(size, time, username, self.conn)
        self.write({"msg": "Packet added"})

class QueryPacketsHandler(BaseHandler):
    def initialize(self, conn):
        self.conn = conn

    @tornado.web.authenticated
    def get(self):
        size_range = self.get_argument('size_range', "0,10000000000")
        time_range = self.get_argument('time_range', "0,10000000000")
        username = self.get_current_user()
        try:
            backend.check_admin(username, self.conn)
            packets = backend.query_packets_admin(size_range, time_range, self.conn)
        except RuntimeError:
            packets = backend.query_packets_user(username, size_range, time_range, self.conn)
        packets = [{"packet_id": packet[0], "packet_size": packet[1], "packet_time": packet[2], "user": packet[3]} for packet in packets]
        self.write(json.dumps(packets))

class GetTotalHandler(BaseHandler):
    def initialize(self, conn):
        self.conn = conn

    @tornado.web.authenticated
    def get(self):
        total_packets, total_size = backend.get_total(self.conn)
        self.write({"total_packets": total_packets, "total_size": total_size})


class GetAverageHandler(BaseHandler):
    def initialize(self, conn):
        self.conn = conn

    @tornado.web.authenticated
    def get(self):
        average = backend.get_average(self.conn)
        self.write({"average": average})

class GetThroughputHandler(BaseHandler):
    def initialize(self, conn):
        self.conn = conn

    @tornado.web.authenticated
    def get(self):
        # save plt to file
        plt = backend.get_throughput(self.conn)
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
    def initialize(self, conn):
        self.conn = conn

    @tornado.web.authenticated
    def get(self):
        # save plt to file
        plt = backend.get_packet_plot(self.conn)
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
    conn = backend.connect_db()
    application = tornado.web.Application([
        (r"/login", LoginHandler, { "conn": conn }),
        (r"/logout", LogoutHandler),
        (r"/add_user", AddUserHandler, { "conn": conn }),
        (r"/remove_user", RemoveUserHandler, { "conn": conn }),
        (r"/list_users", ListUsersHandler, { "conn": conn }),
        (r"/add_packet", AddPacketHandler, { "conn": conn }),
        (r"/query_packets", QueryPacketsHandler, { "conn": conn }),
        (r"/get_total", GetTotalHandler, { "conn": conn }),
        (r"/get_average", GetAverageHandler, { "conn": conn }),
        (r"/get_throughput", GetThroughputHandler, { "conn": conn }),
        (r"/get_packet_plot", GetPacketPlotHandler, { "conn": conn }),
    ], cookie_secret="__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__")
    # run server
    application.listen(5001)
    tornado.ioloop.IOLoop.current().start()

if __name__ == "__main__":
    main()