from django.contrib import admin
from django.urls import path, include
from main import views as main_views

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # Root URL langsung ke landing page
    path('', main_views.landing_page, name='home'),
    
    # Include URL dari aplikasi lain
    path('auth/', include('authorization.urls')),  # Gunakan namespace otomatis dari app_name
    
    # Untuk URL main yang bukan homepage
    path('main/', include('main.urls')),  # Gunakan namespace otomatis dari app_name

    path('voucher/', include('voucher.urls')),
]