import hashlib
import seaborn
import pandas as pd
import matplotlib
matplotlib.use('Agg')
from matplotlib import pyplot as plt
import os
from sqlalchemy import create_engine, inspect
from sqlalchemy.sql import functions
from sqlalchemy.orm import sessionmaker, Session
from model import User, Packet

cur_path = os.path.dirname(os.path.abspath(__file__))


def get_session() -> Session:
    if get_session.maker is None:
        engine = create_engine('sqlite:///' + os.path.join(cur_path, 'database.db'))
        engine.connect()
        get_session.maker = sessionmaker(bind=engine)
    return get_session.maker()
get_session.maker = None


def create_tables():
    engine = create_engine('sqlite:///' + os.path.join(cur_path, 'database.db'))
    engine.connect()
    if inspect(engine).has_table(engine, 'users') and inspect(engine).has_table(engine, 'packets'):
        return
    User.metadata.create_all(engine, checkfirst=True)
    Packet.metadata.create_all(engine, checkfirst=True)
    engine.dispose()


# add admin user with password admin
def add_admin(session: Session):
    # hash password with sha256
    password = hashlib.sha256('admin'.encode('utf-8')).hexdigest()

    admin_user = User(username='admin', password=password, is_admin=1)
    if check_user_exists(admin_user, session):
        return

    session.add(admin_user)
    session.commit()


def login(user: User, session: Session):
    if not check_user_exists(user, session):
        raise RuntimeError('User does not exist')
    user_from_db = session.query(User).filter(User.username == user.username).first()
    if user_from_db.password != user.password:
        raise RuntimeError('Password is incorrect')
    # ok, just return
    return

def check_admin(user: User, session: Session):
    user = session.query(User).filter(User.username == user.username).first()
    if user.is_admin != 1:
        raise RuntimeError('User is not admin')

def add_user(user: User, session: Session):
    if check_user_exists(user, session):
        raise RuntimeError(f'User {user} already exists')
    user.is_admin = 0
    session.add(user)
    session.commit()

def remove_user(user: User, session: Session):
    if not check_user_exists(user, session):
        raise RuntimeError(f'User {user} does not exist')
    session.query(User).filter(User.username == user.username).delete()
    session.commit()

def list_users(session: Session) -> 'list[User]':
    users = session.query(User).all()
    return users

def check_user_exists(user: User, session: Session):
    return session.query(User).filter(User.username == user.username).first() is not None

def add_packet(packet: Packet, session: Session):
    last_packet = session.query(Packet).order_by(Packet.packet_id.desc()).first()
    if last_packet is None:
        packet_id = 1
    else:
        packet_id = last_packet.packet_id + 1
    packet.packet_id = packet_id
    session.add(packet)
    session.commit()

def query_packets_user(user: User, size_range, time_range, session: Session) -> 'list[Packet]':
    size_min, size_max = size_range.split(',')
    time_min, time_max = time_range.split(',')
    packets = session.query(Packet).filter(Packet.user == user, Packet.size.between(size_min, size_max), Packet.time.between(time_min, time_max)).all()
    return packets

def query_packets_admin(size_range, time_range, session: Session) -> 'list[Packet]':
    size_min, size_max = size_range.split(',')
    time_min, time_max = time_range.split(',')
    packets = session.query(Packet).filter(Packet.size.between(size_min, size_max), Packet.time.between(time_min, time_max)).all()
    return packets

def get_total(session: Session):
    total_packets = session.query(Packet).count()
    total_size = session.query(functions.sum(Packet.size)).scalar()
    return total_packets, total_size

def get_average(session: Session):
    total_packets, total_size = get_total(session)
    return total_size / total_packets

def get_packet_plot(session: Session) -> plt:
    packets = session.query(Packet.size, Packet.time).all()
    # visuzalize throughput with scatter plot
    df = pd.DataFrame(packets, columns=['packet_size', 'packet_time'])
    # set index as pakcet_time
    df.set_index('packet_time', inplace=True)
    df = df.groupby('packet_time').sum()
    plt.clf()
    seaborn.scatterplot(x='packet_time', y='packet_size', data=df)
    return plt

def get_throughput(session: Session) -> plt:
    packets = session.query(Packet.size, Packet.time).all()
    # visuzalize throughput with line plot
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