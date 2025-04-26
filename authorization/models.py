from django.db import models

class Role(models.Model):
    # No need to create custom id field, Django will create it automatically
    role_name = models.CharField(max_length=50)

    def __str__(self):
        return self.role_name

class AppIcon(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    image = models.ImageField(upload_to='app_icons/')
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.name

class Permission(models.Model):
    permission_name = models.CharField(max_length=100)

    def __str__(self):
        return self.permission_name

class Role_Permission(models.Model):
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

    class Meta:
        unique_together = ('role', 'permission')
        
    def __str__(self):
        return f"{self.role.role_name} - {self.permission.permission_name}"
    

class Pengguna(models.Model):
    email = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255)
    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True)

    def __str__(self):
        return self.email

class OTPDevice(models.Model):
    pengguna = models.OneToOneField(Pengguna, on_delete=models.CASCADE, related_name='otp_device')
    secret_key = models.CharField(max_length=50)
    last_verified_counter = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"OTP Device for {self.pengguna.email}"

class Admin(models.Model):
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