from django.urls import path
from . import views

app_name = 'voucher'

urlpatterns = [
    path('', views.daftar_voucher, name='daftar_voucher'),
    path('tukar/<int:voucher_id>/', views.tukar_voucher, name='tukar_voucher'),
    path('riwayat/', views.riwayat_penukaran, name='riwayat_penukaran'),
]