from flask import Flask, request, jsonify, send_file
import flask_cors
from flask_jwt_extended import (
    JWTManager,
    jwt_required,
    create_access_token,
    get_jwt_identity,
    get_jwt,
)
from gevent.pywsgi import WSGIServer
import backend
from http import HTTPStatus
import hashlib
import argparse
from io import BytesIO

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "test" # replace with your secret key
flask_cors.CORS(app)
jwt = JWTManager(app)
conn = backend.connect_db()
backend.create_tables(conn)
backend.add_admin(conn)

blacklist = set()
logger = app.logger

@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return jti in blacklist

# login route
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if username is None or password is None:
        return jsonify({"msg": "Missing username or password"}), HTTPStatus.BAD_REQUEST
    # hash password with sha256
    password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    try:
        backend.login(username, password, conn)
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), HTTPStatus.OK
    except RuntimeError as ex:
        logger.error(ex)
        return jsonify({"msg": "Bad username or password"}), HTTPStatus.UNAUTHORIZED

# logout route
@app.route('/logout', methods=['DELETE'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    blacklist.add(jti)
    return jsonify({"msg": "Successfully logged out"}), HTTPStatus.OK

# add user route
@app.route('/add_user', methods=['POST'])
@jwt_required()
def add_user():
    try:
        backend.check_admin(get_jwt_identity(), conn)
    except RuntimeError:
        return jsonify({"msg": "You are not admin"}), HTTPStatus.FORBIDDEN
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if username is None or password is None:
        return jsonify({"msg": "Missing username or password"}), HTTPStatus.BAD_REQUEST
    if backend.check_user_exists(username, conn):
        return jsonify({"msg": "User already exists"}), HTTPStatus.BAD_REQUEST
    # hash password with sha256
    password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    backend.add_user(username, password, conn)
    return jsonify({"msg": "User added"}), HTTPStatus.OK

# remove user route
@app.route('/remove_user', methods=['DELETE'])
@jwt_required()
def remove_user():
    try:
        backend.check_admin(get_jwt_identity(), conn)
    except RuntimeError:
        return jsonify({"msg": "You are not admin"}), HTTPStatus.FORBIDDEN
    username = request.json.get('username', None)
    if username is None:
        return jsonify({"msg": "Missing username"}), HTTPStatus.BAD_REQUEST
    if not backend.check_user_exists(username, conn):
        return jsonify({"msg": "User does not exist"}), HTTPStatus.BAD_REQUEST
    backend.remove_user(username, conn)
    return jsonify({"msg": "User removed"}), HTTPStatus.OK

# list users route
@app.route('/list_users', methods=['GET'])
@jwt_required()
def list_users():
    try:
        backend.check_admin(get_jwt_identity(), conn)
    except RuntimeError:
        return jsonify({"msg": "You are not admin"}), HTTPStatus.FORBIDDEN
    users = backend.list_users(conn)
    users = [{"username": user[0], "password": user[1], "is_admin": user[2]} for user in users]
    return jsonify(users), HTTPStatus.OK

# add packet route
@app.route('/add_packet', methods=['POST'])
@jwt_required()
def add_packet():
    size = request.json.get('size', None)
    time = request.json.get('time', None)
    username = get_jwt_identity()
    if size is None or time is None:
        return jsonify({"msg": "Missing size or time"}), HTTPStatus.BAD_REQUEST
    backend.add_packet(size, time, username, conn)
    return jsonify({"msg": "Packet added"}), HTTPStatus.OK

# query packets route
@app.route('/query_packets', methods=['GET'])
@jwt_required()
def query_packets():
    size_range = request.args.get('size_range', "0,10000000000")
    time_range = request.args.get('time_range', "0,10000000000")
    username = get_jwt_identity()
    try:
        backend.check_admin(username, conn)
        packets = backend.query_packets_admin(size_range, time_range, conn)
    except RuntimeError:
        packets = backend.query_packets_user(username, size_range, time_range, conn)
    packets = [{"packet_id": packet[0], "packet_size": packet[1], "packet_time": packet[2], "user": packet[3]} for packet in packets]
    return jsonify(packets), HTTPStatus.OK

# get total route
@app.route('/get_total', methods=['GET'])
@jwt_required()
def get_total():
    total_packets, total_size = backend.get_total(conn)
    return jsonify({"total_packets": total_packets, "total_size": total_size}), HTTPStatus.OK

# get average route
@app.route('/get_average', methods=['GET'])
@jwt_required()
def get_average():
    average_size = backend.get_average(conn)
    return jsonify({"average_size": average_size})

# get throughput route
@app.route('/get_throughput', methods=['GET'])
@jwt_required()
def get_throughput():
    # save plt to file
    plt = backend.get_throughput(conn)
    # get figure and set it's size to 12inch x 8inch
    fig = plt.gcf()
    fig.set_size_inches(12, 8)
    
    buf = BytesIO()
    plt.savefig(buf, format='png')
    # send file to client
    return send_file(buf, mimetype='image/png')


# get packet plot
@app.route('/get_packet_plot', methods=['GET'])
@jwt_required()
def get_packet_plot():
    # save plt to file
    plt = backend.get_packet_plot(conn)
    # get figure and set it's size to 12inch x 8inch
    fig = plt.gcf()
    fig.set_size_inches(12, 8)
    
    buf = BytesIO()
    plt.savefig(buf, format='png')
    # send file to client
    return send_file(buf, mimetype='image/png')

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
    http_server =  (
            WSGIServer("0.0.0.0:5000", app, keyfile=options.keyfile, certfile=options.certfile) 
            if use_https else 
            WSGIServer( "0.0.0.0:5000", app))
    http_server.serve_forever()