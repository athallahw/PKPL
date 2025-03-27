from django.contrib import admin
from django.urls import path
from main import views

app_name = 'main'

urlpatterns = [
    path('/statuskesehatan', views.show_status, name='show_status'),
    # path('', views.playing_with_neon_view, name='neon_data'),
]
