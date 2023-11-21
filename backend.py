import sqlite3
import hashlib
import seaborn
import pandas as pd
from matplotlib import pyplot as plt

SALT = 'salt'

def create_tables(conn: sqlite3.Connection):
    c = conn.cursor()
    # Create table for users. Passwords should be hashed and salted.
    c.execute('''CREATE TABLE IF NOT EXISTS users
                (username text, password text, is_admin integer)''')
    
    # Create table for packets
    # packet_time is when the packet was sent
    c.execute('''CREATE TABLE IF NOT EXISTS packets
                (packet_id integer, packet_size integer, packet_time integer, user text)''')
    conn.commit()

# add admin user with password admin
def add_admin(conn: sqlite3.Connection):   
    c = conn.cursor()
    password = 'admin'
    # check if admin user exists
    c.execute("SELECT * FROM users WHERE username = 'admin'")
    user = c.fetchone()
    if user is not None:
        return


    # hash password with sha256
    password = password + SALT
    password = hashlib.sha256(password.encode('utf-8')).hexdigest()

    c.execute("INSERT INTO users VALUES ('admin', ?, 1)", (password,))
    conn.commit()


# check user and password against database
def login_args(args, conn: sqlite3.Connection):
    username = args.login_username
    password = args.login_password
    return login(username, password, conn)

def login(username, password, conn: sqlite3.Connection):
    # hash password with sha256
    password = password + SALT
    password = hashlib.sha256(password.encode('utf-8')).hexdigest()

    # check if user exists
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    if user is None:
        print('User does not exist')
        exit()

    # check if password is correct
    c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    user = c.fetchone()
    if user is None:
        print('Password is incorrect')
        exit()

def check_admin(username, conn: sqlite3.Connection):
    # check if user is admin
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ? AND is_admin = 1", (username,))
    user = c.fetchone()
    if user is None:
        print('User is not admin')
        exit()

def add_user(username, password, conn: sqlite3.Connection):
    # hash password with sha256
    password = password + SALT
    password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    c = conn.cursor()
    c.execute("INSERT INTO users VALUES (?, ?, 0)", (username, password))
    conn.commit()

def remove_user(username, conn: sqlite3.Connection):
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()


def list_users(conn: sqlite3.Connection):
    c = conn.cursor()
    c.execute("SELECT * FROM users")
    users = c.fetchall()
    return users

def add_packet(size, time, username, conn: sqlite3.Connection):
    c = conn.cursor()
    c.execute("SELECT MAX(packet_id) FROM packets")
    packet_id = c.fetchone()[0]
    if packet_id is None:
        packet_id = 0
    else:
        packet_id += 1

    c.execute("INSERT INTO packets VALUES (?, ?, ?, ?)", (packet_id, size, time, username))
    conn.commit()

def query_packets(size_range, time_range, conn: sqlite3.Connection):
    size_min, size_max = size_range.split(',')
    time_min, time_max = time_range.split(',')
    c = conn.cursor()
    c.execute("SELECT * FROM packets WHERE packet_size BETWEEN ? AND ? AND packet_time BETWEEN ? AND ?", (size_min, size_max, time_min, time_max))
    packets = c.fetchall()
    return packets

def get_total(conn: sqlite3.Connection):
    c = conn.cursor()
    c.execute("SELECT COUNT(packet_id), SUM(packet_size) FROM packets")
    total = c.fetchone()
    total_packets, total_size = total
    return total_packets, total_size

def get_average(conn: sqlite3.Connection):
    c = conn.cursor()
    c.execute("SELECT AVG(packet_size) FROM packets")
    average = c.fetchone()
    return average[0]

def get_throughput(conn: sqlite3.Connection) -> plt:
    c = conn.cursor()
    c.execute("SELECT packet_size, packet_time, user FROM packets")
    packets = c.fetchall()
    # visuzalize throughput with bar chart using seaborn
    df = pd.DataFrame(packets, columns=['packet_size', 'packet_time', 'user'])
    seaborn.barplot(x='packet_time', y='packet_size', data=df, hue='user')
    return plt