from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    username = Column(String(250), primary_key=True)
    password = Column(String(250), nullable=False)
    is_admin = Column(Integer, nullable=False)

    def __str__(self):
        return f'username: {self.username}, password: {self.password}, is_admin: {self.is_admin}'
    
    def __repr__(self):
        return f'username: {self.username}, password: {self.password}, is_admin: {self.is_admin}'
    
    def to_dict(self):
        return {
            "username": self.username,
            "password": self.password,
            "is_admin": self.is_admin
        }


class Packet(Base):
    __tablename__ = 'packets'
    packet_id = Column(Integer, primary_key=True)
    size = Column(Integer, nullable=False, name='packet_size')
    time = Column(Integer, nullable=False, name='packet_time')
    username = Column(String(250), ForeignKey('users.username'), name='user')
    user = relationship(User)

    def __str__(self):
        return f'packet_id: {self.packet_id}, size: {self.size}, time: {self.time}, username: {self.username}'
    
    def __repr__(self):
        return f'packet_id: {self.packet_id}, size: {self.size}, time: {self.time}, username: {self.username}'
    
    def to_dict(self):
        return {
            "packet_id": self.packet_id,
            "size": self.size,
            "time": self.time,
            "username": self.username
        }
