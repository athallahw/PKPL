from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from .models import Voucher, PenukaranVoucher
from authorization.models import Pengguna, Normal

def daftar_voucher(request):
    # Cek apakah user sudah login
    is_logged_in = 'user_id' in request.session
    
    if is_logged_in:
        user_id = request.session.get('user_id')
        # Jika user sudah login, ambil data poin
        try:
            pengguna = Pengguna.objects.get(id=user_id)
            normal_user = Normal.objects.get(pengguna=pengguna)
            poin = normal_user.poin or 0
            display_name = normal_user.nama or pengguna.email
        except (Pengguna.DoesNotExist, Normal.DoesNotExist):
            poin = 0
            display_name = request.session.get('display_name', 'User')
    else:
        poin = 0
        display_name = "Tamu"
    
    # Ambil semua voucher
    vouchers = Voucher.objects.all().order_by('-id_voucher')
    
    context = {
        'vouchers': vouchers,
        'is_logged_in': is_logged_in,
        'user_name': display_name,
        'poin': poin
    }
    
    return render(request, 'voucher/daftar_voucher.html', context)

def tukar_voucher(request, voucher_id):
    # Cek apakah user sudah login
    if 'user_id' not in request.session:
        messages.error(request, "Silakan login terlebih dahulu")
        return redirect('auth:sign_in')
    
    user_id = request.session.get('user_id')
    
    try:
        pengguna = Pengguna.objects.get(id=user_id)
        normal_user = Normal.objects.get(pengguna=pengguna)
        poin_user = normal_user.poin or 0
    except (Pengguna.DoesNotExist, Normal.DoesNotExist):
        messages.error(request, "Data pengguna tidak ditemukan")
        return redirect('voucher:daftar_voucher')
    
    voucher = get_object_or_404(Voucher, id_voucher=voucher_id)
    
    # Cek apakah poin cukup
    if poin_user < voucher.jumlah_potongan:
        messages.error(request, f"Poin Anda tidak cukup. Dibutuhkan {voucher.jumlah_potongan} poin")
        return redirect('voucher:daftar_voucher')
    
    if request.method == 'POST':
        # Kurangi poin pengguna
        normal_user.poin = poin_user - voucher.jumlah_potongan
        normal_user.save()
        
        # Buat catatan penukaran
        PenukaranVoucher.objects.create(
            pengguna=pengguna,
            voucher=voucher,
            poin_digunakan=voucher.jumlah_potongan,
            status='completed'
        )
        
        messages.success(request, f"Berhasil menukar voucher {voucher.nama_voucher}")
        return redirect('voucher:riwayat_penukaran')
    
    # Tampilkan halaman konfirmasi
    context = {
        'voucher': voucher,
        'poin_user': poin_user
    }
    return render(request, 'voucher/konfirmasi_tukar.html', context)

def riwayat_penukaran(request):
    # Cek apakah user sudah login
    if 'user_id' not in request.session:
        messages.error(request, "Silakan login terlebih dahulu")
        return redirect('auth:sign_in')
    
    user_id = request.session.get('user_id')
    
    try:
        pengguna = Pengguna.objects.get(id=user_id)
        normal_user = Normal.objects.get(pengguna=pengguna)
        poin = normal_user.poin or 0
        display_name = normal_user.nama or pengguna.email
    except (Pengguna.DoesNotExist, Normal.DoesNotExist):
        poin = 0
        display_name = request.session.get('display_name', 'User')
    
    # Ambil riwayat penukaran
    riwayat = PenukaranVoucher.objects.filter(pengguna=pengguna).order_by('-tanggal_penukaran')
    
    context = {
        'riwayat': riwayat,
        'user_name': display_name,
        'poin': poin,
        'is_logged_in': True
    }
    
    return render(request, 'voucher/riwayat_penukaran.html', context)