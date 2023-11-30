import requests

login_url = 'http://127.0.0.1:5000/login'

# login as admin
r = requests.post(login_url, json={"username": "admin", "password": "admin"})
token = r.json()['access_token']

# query packets
r = requests.get('http://127.0.0.1:5000/query_packets', headers={'Authorization': f'Bearer {token}'})
print(r.json())

# total packets
r = requests.get('http://127.0.0.1:5000/get_total', headers={'Authorization': f'Bearer {token}'})
print(r.json())

# average size
r = requests.get('http://127.0.0.1:5000/get_average', headers={'Authorization': f'Bearer {token}'})
print(r.json())

# throughput plot
r = requests.get('http://127.0.0.1:5000/get_throughput', headers={'Authorization': f'Bearer {token}'})
with open('get_throughput.png', 'wb') as f:
    f.write(r.content)

# packets plot
r = requests.get('http://127.0.0.1:5000/get_packet_plot', headers={'Authorization': f'Bearer {token}'})
with open('get_packet_plot.png', 'wb') as f:
    f.write(r.content)