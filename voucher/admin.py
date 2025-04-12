from django.contrib import admin
from .models import Voucher, PenukaranVoucher

@admin.register(Voucher)
class VoucherAdmin(admin.ModelAdmin):
    list_display = ('id_voucher', 'nama_voucher', 'jumlah_potongan', 'tgl_penukaran')
    search_fields = ('nama_voucher',)

@admin.register(PenukaranVoucher)
class PenukaranVoucherAdmin(admin.ModelAdmin):
    list_display = ('pengguna', 'voucher', 'tanggal_penukaran', 'poin_digunakan', 'status')
    list_filter = ('status', 'tanggal_penukaran')
    search_fields = ('pengguna__email', 'voucher__nama_voucher')