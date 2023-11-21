import sqlite3
import argparse
from functools import partial
import backend

# check user and password against database
def login(args, conn: sqlite3.Connection):
    username = args.login_username
    password = args.login_password
    return backend.login(username, password, conn)

def check_admin(args, conn: sqlite3.Connection):
    return backend.check_admin(args.login_username, conn)

# add user to database
def add_user(args, conn: sqlite3.Connection):
    backend.check_admin(args.login_username, conn)
    username = args.username
    password = args.password
    backend.add_user(username, password, conn)
    print("User added")


def remove_user(args, conn: sqlite3.Connection):
    backend.check_admin(args.login_username, conn)
    backend.remove_user(args.username, conn)
    print("User removed")


def list_users(args, conn: sqlite3.Connection):
    backend.check_admin(args.login_username, conn)
    users = backend.list_users(conn)
    # print header of a table
    print('username\tpassword\tis_admin')
    # print users in a nice format
    for user in users:
        print(f"{user[0]}\t{user[1]}\t{user[2]}")


def add_packet(args, conn: sqlite3.Connection):
    size = args.size
    time = args.time
    username = args.login_username
    backend.add_packet(size, time, username, conn)
    print("Packet added")

def query_packets(args, conn: sqlite3.Connection):
    size_range = args.size_range
    time_range = args.time_range
    packets = backend.query_packets(size_range, time_range, conn)
    # print header of a table
    print('packet_id\tpacket_size\tpacket_time\tuser')\
    # print rest of the table
    for packet in packets:
        print(f"{packet[0]}\t{packet[1]}\t{packet[2]}\t{packet[3]}")

def get_total(args, conn: sqlite3.Connection):
    total_packets, total_size = backend.get_total(conn)
    print(f'total packets: {total_packets}')
    print(f'total size: {total_size}')

def get_average(args, conn: sqlite3.Connection):
    average = backend.get_average(conn)
    print(f'average packet size: {average[0]}')

def get_throughput(args, conn: sqlite3.Connection):
    local_plt = backend.get_throughput(conn)
    local_plt.show()

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
    query_packets_parser.add_argument("-t", "--time_range", help="packet time; format: min,max", default='0,1000000000')

    # add cli suboption to get info about total package count/size
    get_total_parser = subparsers.add_parser(name="get_total", help='get total package count/size')

    # add cli suboption to get info about average packet size
    get_average_parser = subparsers.add_parser(name="get_average", help='get average packet size')

    # add cli suboption to get info about vizualized throughput
    get_throughput_parser = subparsers.add_parser(name="get_throughput", help='get vizualized throughput')

    conn = sqlite3.connect('database.db')
    add_user_parser.set_defaults(func=partial(add_user, conn=conn))
    remove_user_parser.set_defaults(func=partial(remove_user, conn=conn))
    list_users_parser.set_defaults(func=partial(list_users, conn=conn))
    add_packet_parser.set_defaults(func=partial(add_packet, conn=conn))
    query_packets_parser.set_defaults(func=partial(query_packets, conn=conn))
    get_total_parser.set_defaults(func=partial(get_total, conn=conn))
    get_average_parser.set_defaults(func=partial(get_average, conn=conn))
    get_throughput_parser.set_defaults(func=partial(get_throughput, conn=conn))

    backend.create_tables(conn)
    backend.add_admin(conn)

    args = parser.parse_args()
    login(args, conn)
    args.func(args)

if __name__ == '__main__':
    main()