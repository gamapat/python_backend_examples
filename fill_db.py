import backend
import sqlite3
import hashlib
import random
import string

conn = sqlite3.connect('database.db')
backend.create_tables(conn)
backend.add_admin(conn)

# remove all users except admin
users = backend.list_users(conn)
for user in users:
    if user[0] != 'admin':
        backend.remove_user(user[0], conn)

# add 20 users with random names and passwords
# store user creds in plaintext in json file
with open('creds.json', 'w', encoding="utf-8") as f:
    user_creds = [{"un": "admin", "pw": "admin"}]
    for i in range(20):
        username = ''.join(random.choices(string.ascii_lowercase, k=10))
        password = ''.join(random.choices(string.ascii_lowercase, k=10))
        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        backend.add_user(username, hashed_password, conn)
        user_creds.append({"un": username, "pw": password})
    import json
    json.dump(user_creds, f)


# remove all packets
cur = conn.cursor()
cur.execute('DELETE FROM packets')
conn.commit()

# add random number of packets for each user
cur = conn.cursor()
id_counter = 1
for user in backend.list_users(conn):
    for i in range(random.randint(1, 500)):
        cur.execute('INSERT INTO packets VALUES (?, ?, ?, ?)', (id_counter, random.randint(1, 4096), random.randint(1700570000, 1700600000), user[0]))
        id_counter+=1

conn.commit()

