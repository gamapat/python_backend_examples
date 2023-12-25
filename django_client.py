import requests

login_url = 'http://127.0.0.1:8000/login'

# login as admin
r = requests.post(login_url, json={"username": "admin", "password": "admin"})
token = r.json()['access_token']

headers = {'Authorization': f'Bearer {token}'}

r = requests.get('http://127.0.0.1:8000/list_users', headers=headers)
print(r.json())
r = requests.delete("http://127.0.0.1:8000/logout", headers=headers)
print(r.text)

r = requests.post(login_url, json={"username": "yeopjnofwd", "password": "fyrmcrkajl"})
token = r.json()['access_token']
headers = {'Authorization': f'Bearer {token}'}

# query packets
r = requests.get('http://127.0.0.1:8000/query_packets', headers=headers)
print(r.json())

# total packets
r = requests.get('http://127.0.0.1:8000/get_total', headers=headers)
print(r.json())

# average size
r = requests.get('http://127.0.0.1:8000/get_average', headers=headers)
print(r.json())

# throughput plot
r = requests.get('http://127.0.0.1:8000/get_throughput', headers=headers)
with open('get_throughput.png', 'wb') as f:
    f.write(r.content)

# packets plot
r = requests.get('http://127.0.0.1:8000/get_packet_plot', headers=headers)
with open('get_packet_plot.png', 'wb') as f:
    f.write(r.content)