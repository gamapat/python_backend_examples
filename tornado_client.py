import requests

url_prefix = 'http://127.0.0.1:5001'

# login as admin
r = requests.post(f"{url_prefix}/login", json={"username": "admin", "password": "admin"})
cookies = r.cookies

r = requests.delete(f"{url_prefix}/logout", cookies=cookies)
print(r.content)

# sleep for 5 seconds
import time
time.sleep(5)

r = requests.post(f"{url_prefix}/login", json={"username": "admin", "password": "admin"})
cookies = r.cookies

# # query packets
# r = requests.get(f'{url_prefix}/query_packets', cookies=cookies)
# print(r.json())

# total packets
r = requests.get(f'{url_prefix}/get_total', cookies=cookies)
print(r.json())

# average size
r = requests.get(f'{url_prefix}/get_average', cookies=cookies)
print(r.json())

# throughput plot
r = requests.get(f'{url_prefix}/get_throughput', cookies=cookies)
with open('get_throughput.png', 'wb') as f:
    f.write(r.content)

# packets plot
r = requests.get(f'{url_prefix}/get_packet_plot', cookies=cookies)
with open('get_packet_plot.png', 'wb') as f:
    f.write(r.content)