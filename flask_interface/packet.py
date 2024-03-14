from flask import blueprints, request, jsonify, send_file
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
import model
import backend
from http import HTTPStatus
from io import BytesIO
import logging

packet = blueprints.Blueprint('packet', __name__)
logger = logging.getLogger("flask_interface")

class Packet(object):
    @packet.route('', methods=['POST'])
    def post():
        verify_jwt_in_request()
        # add packet
        with backend.get_session() as session:
            size = request.json.get('size', None)
            time = request.json.get('time', None)
            if size is None or time is None:
                return jsonify({"msg": "Missing size or time"}), HTTPStatus.BAD_REQUEST
            packet_obj = model.Packet(size, time, get_jwt_identity())
            backend.add_packet(packet_obj, session)
            return jsonify({"msg": "Packet added"}), HTTPStatus.OK

    @packet.route('', methods=['GET'])
    def get():
        verify_jwt_in_request()
        # query packets
        with backend.get_session() as session:
            size_range = request.args.get('size_range', '0,1000000000')
            time_range = request.args.get('time_range', '0,2000000000')
            username = get_jwt_identity()
            user_obj = model.User(username=username, password=None, is_admin=None)
            try:
                backend.check_admin(user_obj, session)
                packets = backend.query_packets_admin(size_range, time_range, session)
            except RuntimeError:
                packets = backend.query_packets_user(user_obj, size_range, time_range, session)
            return jsonify([pckt.to_dict() for pckt in packets]), HTTPStatus.OK

    @packet.route('/total', methods=['GET'])
    def total():
        verify_jwt_in_request()
        # get total
        with backend.get_session() as session:
            total_packets, total_size = backend.get_total(session)
            return jsonify({"total_packets": total_packets, "total_size": total_size}), HTTPStatus.OK
        
    @packet.route('/average', methods=['GET'])
    def average():
        verify_jwt_in_request()
        # get average
        with backend.get_session() as session:
            average = backend.get_average(session)
            return jsonify({"average": average}), HTTPStatus.OK
        
    @packet.route('/plot', methods=['GET'])
    def plot():
        verify_jwt_in_request()
        # get plot
        with backend.get_session() as session:
            plt = backend.get_packet_plot(session)
            # get figure and set it's size to 12inch x 8inch
            fig = plt.gcf()
            fig.set_size_inches(12, 8)
            
            buf = BytesIO()
            plt.savefig(buf, format='png')
            buf.seek(0)
            # send file to client
            return send_file(buf, mimetype='image/png')
        
    @packet.route('/throughput', methods=['GET'])
    def throughput():
        verify_jwt_in_request()
        # get throughput
        with backend.get_session() as session:
            plt = backend.get_throughput(session)
            # get figure and set it's size to 12inch x 8inch
            fig = plt.gcf()
            fig.set_size_inches(12, 8)
            
            buf = BytesIO()
            plt.savefig(buf, format='png')
            buf.seek(0)
            # send file to client
            return send_file(buf, mimetype='image/png')