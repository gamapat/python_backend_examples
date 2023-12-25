import sqlite3
import hashlib
import seaborn
import pandas as pd
import matplotlib
matplotlib.use('Agg')
from matplotlib import pyplot as plt
import os

cur_path = os.path.dirname(os.path.abspath(__file__))

def connect_db():
    conn = sqlite3.connect(os.path.join(cur_path, 'database.db'))
    return conn

def create_tables(conn: sqlite3.Connection):
    c = conn.cursor()
    # Create table for users. Passwords should be hashed.
    c.execute('''CREATE TABLE IF NOT EXISTS users
                (username text, password text, is_admin integer)''')
    
    # Create table for packets
    # packet_time is when the packet was sent
    c.execute('''CREATE TABLE IF NOT EXISTS packets
                (packet_id integer, packet_size integer, packet_time integer, user text)''')
    conn.commit()

# add admin user with password admin
def add_admin(conn: sqlite3.Connection):
    if check_user_exists('admin', conn):
        return

    # hash password with sha256
    password = hashlib.sha256('admin'.encode('utf-8')).hexdigest()

    c = conn.cursor()
    c.execute("INSERT INTO users VALUES ('admin', ?, 1)", (password,))
    conn.commit()


def login(username, hashed_password, conn: sqlite3.Connection):
    # check if user exists
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    if user is None:
        raise RuntimeError('User does not exist')

    # check if password is correct
    c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, hashed_password))
    user = c.fetchone()
    if user is None:
        raise RuntimeError('Password is incorrect')

def check_admin(username, conn: sqlite3.Connection):
    # check if user is admin
    c = conn.cursor()
    print(username)
    c.execute("SELECT * FROM users WHERE username = ? AND is_admin = 1", (username,))
    user = c.fetchone()
    if user is None:
        raise RuntimeError('User is not admin')

def add_user(username, hashed_password, conn: sqlite3.Connection):
    c = conn.cursor()
    c.execute("INSERT INTO users VALUES (?, ?, 0)", (username, hashed_password))
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

def check_user_exists(username, conn: sqlite3.Connection):
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    return user is not None

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

def get_packet_plot(conn: sqlite3.Connection) -> plt:
    c = conn.cursor()
    c.execute("SELECT packet_size, packet_time FROM packets")
    packets = c.fetchall()
    # visuzalize throughput with scatter plot using seaborn
    df = pd.DataFrame(packets, columns=['packet_size', 'packet_time'])
    # set index as pakcet_time
    df.set_index('packet_time', inplace=True)
    df = df.groupby('packet_time').sum()
    plt.clf()
    seaborn.scatterplot(x='packet_time', y='packet_size', data=df)
    return plt

def get_throughput(conn: sqlite3.Connection) -> plt:
    c = conn.cursor()
    c.execute("SELECT packet_size, packet_time FROM packets")
    packets = c.fetchall()
    # visuzalize throughput with line plot using seaborn
    df = pd.DataFrame(packets, columns=['packet_size', 'packet_time'])
    # set index as pakcet_time
    df.set_index('packet_time', inplace=True)
    df = df.groupby('packet_time').sum()
    df = df.reindex(list(range(df.index.min(), df.index.max() + 1)), fill_value=0.0)
    df_rolling_avg = df.rolling(1000).sum()
    # rename column to throughput bytes/s
    df_rolling_avg.rename(columns={'packet_size': 'throughput bytes/s'}, inplace=True)
    plt.clf()
    seaborn.lineplot(x='packet_time', y='throughput bytes/s', data=df_rolling_avg)
    return plt