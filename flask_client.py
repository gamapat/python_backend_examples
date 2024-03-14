import requests

login_url = 'http://127.0.0.1:5000/user/login'

# login as admin
r = requests.post(login_url, json={"username": "mubcvdncdj", "password": "buftuzqldx"})
token = r.json()['access_token']

# add user
r = requests.post('http://127.0.0.1:5000/user', json={"username": "user", "password": "psw"}, headers={'Authorization': f'Bearer {token}'})
print(r.text)

r = requests.get('http://127.0.0.1:5000/user', headers={'Authorization': f'Bearer {token}'})
print(r.json())

# remove user
r = requests.delete('http://127.0.0.1:5000/user', json={"username": "user"}, headers={'Authorization': f'Bearer {token}'})
print(r.text)

r = requests.get('http://127.0.0.1:5000/user', headers={'Authorization': f'Bearer {token}'})
print(r.json())

# query packets
r = requests.get('http://127.0.0.1:5000/packet', headers={'Authorization': f'Bearer {token}'})
print(r.json())

# total packets
r = requests.get('http://127.0.0.1:5000/packet/total', headers={'Authorization': f'Bearer {token}'})
print(r.json())

# average size
r = requests.get('http://127.0.0.1:5000/packet/average', headers={'Authorization': f'Bearer {token}'})
print(r.json())

# throughput plot
r = requests.get('http://127.0.0.1:5000/packet/throughput', headers={'Authorization': f'Bearer {token}'})
with open('get_throughput.png', 'wb') as f:
    f.write(r.content)
# packets plot
r = requests.get('http://127.0.0.1:5000/packet/plot', headers={'Authorization': f'Bearer {token}'})
with open('get_packet_plot.png', 'wb') as f:
    f.write(r.content)
