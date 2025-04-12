from django.db import models

class Pengguna(models.Model):
    email = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255)

    def __str__(self):
        return self.email

class Admin(models.Model):
    # Menggunakan OneToOneField dengan primary_key=True agar 'id' di Admin sama dengan 'id' di Pengguna
    pengguna = models.OneToOneField(
        Pengguna,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name='admin'
    )

    def __str__(self):
        return f"Admin: {self.pengguna.email}"

class Normal(models.Model):
    pengguna = models.OneToOneField(
        Pengguna,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name='normal'
    )
    nama_depan = models.CharField(max_length=255, blank=True, null=True)
    nama_belakang = models.CharField(max_length=255, blank=True, null=True)
    nama = models.CharField(max_length=255, blank=True, null=True)
    tanggal_lahir = models.DateField(blank=True, null=True)
    tinggi_badan = models.IntegerField(blank=True, null=True)
    gender = models.CharField(max_length=50, blank=True, null=True)
    umur = models.IntegerField(blank=True, null=True)
    poin = models.IntegerField(blank=True, null=True)

    def __str__(self):
        return f"User: {self.nama if self.nama else self.pengguna.email}"