from sqlalchemy.orm import Session
import argparse
from functools import partial
import backend
import hashlib
from model import User, Packet

# check user and password against database
def login(args, session: Session):
    # hash password with sha256
    password = hashlib.sha256(args.login_password.encode('utf-8')).hexdigest()
    user = User(username=args.login_username, password=password)
    return backend.login(user, session)

# add user to database
def add_user(args, session: Session):
    login_user = User(username=args.login_username, password='', is_admin=0)
    backend.check_admin(login_user, session)
    password = hashlib.sha256(args.password.encode('utf-8')).hexdigest()
    user = User(username=args.username, password=password)
    backend.add_user(user, session)
    print("User added")


def remove_user(args, session: Session):
    login_user = User(username=args.login_username, password='')
    backend.check_admin(login_user, session)
    user = User(username=args.username, password='')
    backend.remove_user(user, session)
    print("User removed")


def list_users(args, session: Session):
    login_user = User(username=args.login_username, password='')
    backend.check_admin(login_user, session)
    users = backend.list_users(session)
    # print header of a table
    print('username\tpassword\tis_admin')
    # print users in a nice format
    for user in users:
        print(f"{user.username}\t{user.password}\t{user.is_admin}")

def add_packet(args, session: Session):
    packet = Packet(size=args.size, time=args.time, username=args.login_username)
    backend.add_packet(packet, session)
    print("Packet added")

def query_packets(args, session: Session):
    size_range = args.size_range
    time_range = args.time_range
    login_user = User(username=args.login_username, password='')
    try:
        backend.check_admin(login_user, session)
        packets = backend.query_packets_admin(size_range, time_range, session)
    except RuntimeError:
        packets = backend.query_packets_user(login_user, size_range, time_range, session)
    # print header of a table
    print('packet_id\tpacket_size\tpacket_time\tuser')
    # print rest of the table
    for packet in packets:
        print(f"{packet.packet_id}\t{packet.size}\t{packet.time}\t{packet.username}")

def get_total(args, session: Session):
    total_packets, total_size = backend.get_total(session)
    print(f'total packets: {total_packets}')
    print(f'total size: {total_size}')

def get_average(args, session: Session):
    average = backend.get_average(session)
    print(f'average packet size: {average}')

def get_throughput(args, session: Session):
    local_plt = backend.get_throughput(session)
    # save to local file
    local_plt.savefig('cli_throughput.png')
    
def get_packet_plot(args, session: Session):
    local_plt = backend.get_packet_plot(session)
    # save to local file
    local_plt.savefig('cli_packets.png')

def main():
    # add cli option to login
    parser = argparse.ArgumentParser()
    # username with short option -u and long option --username
    parser.add_argument("-lu", "--login_username", help="username", required=True)
    # password with short option -p and long option --password
    parser.add_argument("-lp", "--login_password", help="password", required=True)
    # add cli suboption to add regular user
    subparsers = parser.add_subparsers(required=True)
    add_user_parser = subparsers.add_parser(name="add_user", help='add regular user')
    add_user_parser.add_argument("-u", "--username", help="username", required=True)
    add_user_parser.add_argument("-p", "--password", help="password", required=True)

    # add cli suboption to remove regular user
    remove_user_parser = subparsers.add_parser(name="remove_user", help='remove regular user')
    remove_user_parser.add_argument("-u", "--username", help="username", required=True)

    # add cli suboption to list users
    list_users_parser = subparsers.add_parser(name="list_users", help='list users')

    # add cli suboption to add packet
    add_packet_parser = subparsers.add_parser(name="add_packet", help='add packet')
    add_packet_parser.add_argument("-s", "--size", help="packet size", required=True)
    add_packet_parser.add_argument("-t", "--time", help="packet time", required=True)

    # add cli suboption to query packets based on min max time and min max size
    query_packets_parser = subparsers.add_parser(name="query_packets", help='query packets')
    query_packets_parser.add_argument("-s", "--size_range", help="packet size; format: min,max", default='0,1000000000')
    query_packets_parser.add_argument("-t", "--time_range", help="packet time; format: min,max", default='0,2000000000')

    # add cli suboption to get info about total package count/size
    get_total_parser = subparsers.add_parser(name="get_total", help='get total package count/size')

    # add cli suboption to get info about average packet size
    get_average_parser = subparsers.add_parser(name="get_average", help='get average packet size')

    # add cli suboption to get info about visualized throughput
    get_throughput_parser = subparsers.add_parser(name="get_throughput", help='get visualized throughput')

    # add cli suboption to get info about visualized packets
    get_visualized_packets_parser = subparsers.add_parser(name="get_packet_plot", help='get visualized packets')

    with backend.get_session() as session:
        add_user_parser.set_defaults(func=partial(add_user, session=session))
        remove_user_parser.set_defaults(func=partial(remove_user, session=session))
        list_users_parser.set_defaults(func=partial(list_users, session=session))
        add_packet_parser.set_defaults(func=partial(add_packet, session=session))
        query_packets_parser.set_defaults(func=partial(query_packets, session=session))
        get_total_parser.set_defaults(func=partial(get_total, session=session))
        get_average_parser.set_defaults(func=partial(get_average, session=session))
        get_throughput_parser.set_defaults(func=partial(get_throughput, session=session))
        get_visualized_packets_parser.set_defaults(func=partial(get_packet_plot, session=session))

        backend.create_tables()
        backend.add_admin(session)

        args = parser.parse_args()
        login(args, session)
        args.func(args)

if __name__ == '__main__':
    main()