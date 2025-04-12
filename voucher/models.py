from django.db import models
from django.utils import timezone

class Voucher(models.Model):
    id_voucher = models.AutoField(primary_key=True)
    nama_voucher = models.CharField(max_length=255)
    jumlah_potongan = models.IntegerField()  
    tgl_penukaran = models.DateField(null=True, blank=True)  
    
    def __str__(self):
        return self.nama_voucher

class PenukaranVoucher(models.Model):
    pengguna = models.ForeignKey('authorization.Pengguna', on_delete=models.CASCADE, related_name='penukaran')
    voucher = models.ForeignKey(Voucher, on_delete=models.CASCADE)
    tanggal_penukaran = models.DateTimeField(default=timezone.now)
    poin_digunakan = models.IntegerField()
    status = models.CharField(max_length=20, choices=[
        ('pending', 'Menunggu'),
        ('completed', 'Selesai'),
        ('expired', 'Kadaluarsa')
    ], default='pending')
    
    def __str__(self):
        return f"{self.pengguna.email} - {self.voucher.nama_voucher}"