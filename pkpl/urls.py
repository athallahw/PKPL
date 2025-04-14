from django.contrib import admin
from django.urls import path, include
from main import views as main_views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # Root URL langsung ke landing page
    path('', main_views.landing_page, name='home'),
    
    # Include URL dari aplikasi lain
    path('auth/', include('authorization.urls')),  # Gunakan namespace otomatis dari app_name
    
    # Untuk URL main yang bukan homepage
    path('main/', include('main.urls')),  # Gunakan namespace otomatis dari app_name

    path('voucher/', include('voucher.urls')),
    path('kuesioner/', include('kuesioner.urls')),
    path('statuskesehatan/', include('health_status.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)