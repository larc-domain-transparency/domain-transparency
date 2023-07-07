from django.urls import path

from . import views

urlpatterns = [
    path('', views.monitor, name='monitor'),
    path('getdomaindata', views.getdomaindata, name='getdomaindata'),
]