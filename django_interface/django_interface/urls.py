from django.urls import path
from . import views

urlpatterns = [
    path('login', views.LoginView.as_view(), name='login'),
    path('user', views.User.as_view(), name='user'),
    path('packet', views.Packet.as_view(), name='packet'),
    path('packet/total', views.Total.as_view(), name='total'),
    path('packet/average', views.Average.as_view(), name='average'),
    path('packet/throughput', views.Throughput.as_view(), name='throughput'),
    path('packet/plot', views.PacketPlot.as_view(), name='plot'),
]
