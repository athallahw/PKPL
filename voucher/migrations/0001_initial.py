# Generated by Django 5.2 on 2025-04-12 15:37

import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('authorization', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Voucher',
            fields=[
                ('id_voucher', models.AutoField(primary_key=True, serialize=False)),
                ('nama_voucher', models.CharField(max_length=255)),
                ('jumlah_potongan', models.IntegerField()),
                ('tgl_penukaran', models.DateField(blank=True, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='PenukaranVoucher',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('tanggal_penukaran', models.DateTimeField(default=django.utils.timezone.now)),
                ('poin_digunakan', models.IntegerField()),
                ('status', models.CharField(choices=[('pending', 'Menunggu'), ('completed', 'Selesai'), ('expired', 'Kadaluarsa')], default='pending', max_length=20)),
                ('pengguna', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='penukaran', to='authorization.pengguna')),
                ('voucher', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='voucher.voucher')),
            ],
        ),
    ]
