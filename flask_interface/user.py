from flask import blueprints, request, jsonify
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request, create_access_token, get_jwt
import model
import backend
from http import HTTPStatus
import hashlib
import logging
from jwt_ext import jwt

user = blueprints.Blueprint('user', __name__)
logger = logging.getLogger("flask_interface")

@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return jti in User.blacklist

class User(object):
    blacklist = set()
    
    @user.route('', methods=['GET'])
    def get():
        verify_jwt_in_request()
        # get list of users
        with backend.get_session() as session:
            user_obj = model.User(username=get_jwt_identity(), password=None, is_admin=None)
            try:
                backend.check_admin(user_obj, session)
            except RuntimeError:
                return jsonify({"msg": "You are not admin"}), HTTPStatus.FORBIDDEN
            return jsonify([usr.to_dict() for usr in backend.list_users(session)]), HTTPStatus.OK

    @user.route('', methods=['POST'])
    def post():
        verify_jwt_in_request()
        # add user
        with backend.get_session() as session:
            user_obj = model.User(username=get_jwt_identity(), password=None, is_admin=None)
            try:
                backend.check_admin(user_obj, session)
            except RuntimeError:
                return jsonify({"msg": "You are not admin"}), HTTPStatus.FORBIDDEN
            username = request.json.get('username', None)
            password = request.json.get('password', None)
            is_admin = request.json.get('is_admin', 0)
            if username is None or password is None:
                return jsonify({"msg": "Missing username or password"}), HTTPStatus.BAD_REQUEST
            user_obj = model.User(username=username, password=password, is_admin=is_admin)
            backend.add_user(user_obj, session)
            return jsonify({"msg": "User added"}), HTTPStatus.OK

    @user.route('', methods=['DELETE'])
    def delete():
        verify_jwt_in_request()
        # remove user
        with backend.get_session() as session:
            user_obj = model.User(username=get_jwt_identity(), password=None, is_admin=None)
            try:
                backend.check_admin(user_obj, session)
            except RuntimeError:
                return jsonify({"msg": "You are not admin"}), HTTPStatus.FORBIDDEN
            username = request.json.get('username', None)
            if username is None:
                return jsonify({"msg": "Missing username"}), HTTPStatus.BAD_REQUEST
            user_obj = model.User(username=username, password=None, is_admin=None)
            backend.remove_user(user_obj, session)
            return jsonify({"msg": "User removed"}), HTTPStatus.OK
        
    @user.route('/login', methods=['POST'])
    def login():
        # login
        username = request.json.get('username', None)
        password = request.json.get('password', None)
        if username is None or password is None:
            return jsonify({"msg": "Missing username or password"}), HTTPStatus.BAD_REQUEST
        with backend.get_session() as session:
            password = hashlib.sha256(password.encode('utf-8')).hexdigest()
            user_obj = model.User(username=username, password=password, is_admin=None)
            try:
                backend.login(user_obj, session)
                access_token = create_access_token(identity=username)
                User.blacklist.discard(access_token)
                return jsonify(access_token=access_token), HTTPStatus.OK
            except RuntimeError as ex:
                logger.error(ex)
                return jsonify({"msg": "Bad username or password"}), HTTPStatus.UNAUTHORIZED
            
    @user.route('/logout', methods=['POST'])
    def logout():
        verify_jwt_in_request()
        # logout
        jti = get_jwt()['jti']
        # if already in blacklist - return message that user is already logged out
        if jti in User.blacklist:
            return jsonify({"msg": "Already logged out"}), HTTPStatus.OK
        User.blacklist.add(jti)
        return jsonify({"msg": "Successfully logged out"}), HTTPStatus.OK