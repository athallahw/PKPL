
from django.urls import path, include
from . import views

app_name = 'main'

urlpatterns = [
    path('', views.landing_page, name='landing_page'),
    path('kuesioner/', include('kuesioner.urls')),
    
]