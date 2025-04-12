from django.urls import path
from . import views

app_name = 'auth'

urlpatterns = [
    path('sign-in/', views.sign_in, name='sign_in'),
    path('sign-up/', views.sign_up, name='sign_up'),
    path('logout/', views.logout, name='logout'),
    path('setup-otp/', views.setup_otp, name='setup_otp'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
]