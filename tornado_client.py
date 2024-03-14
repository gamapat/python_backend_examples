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

# add user
r = requests.post(f'{url_prefix}/user', json={"username": "user", "password": "psw"}, cookies=cookies)
print(r.text)

r = requests.get(f'{url_prefix}/user', cookies=cookies)
print(r.json())

# remove user
r = requests.delete(f'{url_prefix}/user', json={"username": "user"}, cookies=cookies)
print(r.text)

r = requests.get(f'{url_prefix}/user', cookies=cookies)
print(r.json())


# query packets
r = requests.get(f'{url_prefix}/packet', cookies=cookies)
print(r.json())

# total packets
r = requests.get(f'{url_prefix}/packet/total', cookies=cookies)
print(r.json())

# average size
r = requests.get(f'{url_prefix}/packet/average', cookies=cookies)
print(r.json())

# throughput plot
r = requests.get(f'{url_prefix}/packet/throughput', cookies=cookies)
with open('get_throughput.png', 'wb') as f:
    f.write(r.content)

# packets plot
r = requests.get(f'{url_prefix}/packet/plot', cookies=cookies)
with open('get_packet_plot.png', 'wb') as f:
    f.write(r.content)