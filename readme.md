install conda
install requirements. Python path will be assumed ./.conda/python.exe
```
./.conda/python.exe -m pip install -r requirements.txt
```
# CLI examples
```
./.conda/python.exe cli_interface.py -lu admin -lp admin list_users
./.conda/python.exe cli_interface.py -lu admin -lp admin add_user -u user1 -p passwd1
./.conda/python.exe cli_interface.py -lu admin -lp admin remove_user -u user1
./.conda/python.exe cli_interface.py -lu user1 -lp passwd1 add_packet -s 1234 --time 1711191234
./.conda/python.exe cli_interface.py -lu user1 -lp passwd1 query_packets -s 0,4096 --time 1700000000,1800000000
./.conda/python.exe cli_interface.py -lu user1 -lp passwd1 get_total
./.conda/python.exe cli_interface.py -lu user1 -lp passwd1 get_average
./.conda/python.exe cli_interface.py -lu user1 -lp passwd1 get_throughput
./.conda/python.exe cli_interface.py -lu user1 -lp passwd1 get_packet_plot
```
# Test flask interface
first console
```
./.conda/python.exe flask_interface.flask_interface
```
second console
```
./.conda/python.exe flask_client
```

# Test tornado interface
first console
```
./.conda/python.exe tornado_interface
```
second console
```
./.conda/python.exe tornado_client
```

# Test django interface
first console
```
cd django_interface
../.conda/python.exe manage.py runserver
```
second console
```
./.conda/python.exe django_client
```