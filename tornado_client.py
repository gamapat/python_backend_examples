import requests

login_url = 'http://127.0.0.1:5001/login'

# login as admin
r = requests.post(login_url, json={"username": "admin", "password": "admin"})
cookies = r.cookies

# query packets
r = requests.get('http://127.0.0.1:5001/query_packets', cookies=cookies)
print(r.json())

# total packets
r = requests.get('http://127.0.0.1:5001/get_total', cookies=cookies)
print(r.json())

# average size
r = requests.get('http://127.0.0.1:5001/get_average', cookies=cookies)
print(r.json())

# throughput plot
r = requests.get('http://127.0.0.1:5001/get_throughput', cookies=cookies)
with open('get_throughput.png', 'wb') as f:
    f.write(r.content)

# packets plot
r = requests.get('http://127.0.0.1:5001/get_packet_plot', cookies=cookies)
with open('get_packet_plot.png', 'wb') as f:
    f.write(r.content)