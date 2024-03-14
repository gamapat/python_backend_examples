import os
parent_parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
import sys
sys.path.append(parent_parent_dir)

from flask import Flask
from gevent.pywsgi import WSGIServer
import argparse
import backend
from packet import packet
from user import user
from jwt_ext import jwt

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "test" # replace with your secret key
app.register_blueprint(user, url_prefix='/user')
app.register_blueprint(packet, url_prefix='/packet')

logger = app.logger

if __name__ == '__main__':    
    parser = argparse.ArgumentParser(prog="flask_interface")
    parser.add_argument(
        "-c", "--certfile", help="path to tls certificate", type=str, required=False
    )
    parser.add_argument(
        "-k", "--keyfile", help="path to tls key", type=str, required=False
    )
    options = parser.parse_args()
    use_https = (
        "certfile" in dir(options)
        and options.certfile
        and "keyfile" in dir(options)
        and options.keyfile
    )
    with backend.get_session() as session:
        backend.create_tables()
        backend.add_admin(session)
    jwt.init_app(app)
    http_server =  (
            WSGIServer("0.0.0.0:5000", app, keyfile=options.keyfile, certfile=options.certfile) 
            if use_https else 
            WSGIServer( "0.0.0.0:5000", app))
    http_server.serve_forever()