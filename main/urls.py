"""
URL configuration for pkpl project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from main import views as main_views
from authorization import views as auth_views

app_name = 'main'

urlpatterns = [
    path('admin/', admin.site.urls),
    # Ubah route default ke halaman sign in
    path('', auth_views.sign_in, name='sign_in'),
    
    # Jika masih ingin menyediakan route untuk landing page,
    # Anda bisa memberikan URL khusus misalnya:
    path('landing/', main_views.landing_page, name='landing_page'),
]
