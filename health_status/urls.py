from django.contrib import admin
from django.urls import path
from health_status import views

app_name = 'statuskesehatan'

urlpatterns = [
    path('', views.show_status, name='show_status'),
    # path('', views.playing_with_neon_view, name='neon_data'),
]
