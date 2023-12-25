from django.urls import path
from . import views

urlpatterns = [
    path('login', views.login_view, name='login'),
    path('logout', views.logout_view, name='logout'),
    path('add_user', views.add_user, name='add_user'),
    path('remove_user', views.remove_user, name='remove_user'),
    path('list_users', views.list_users, name='list_users'),
    path('query_packets', views.query_packets, name='query_packets'),
    path('add_packet', views.add_packet, name='add_packet'),
    path('get_total', views.get_total, name='get_total'),
    path('get_average', views.get_average, name='get_average'),
    path('get_throughput', views.get_throughput, name='get_throughput'),
    path('get_packet_plot', views.get_packet_plot, name='get_packet_plot'),
]
