from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.utils import timezone
from django.db import transaction
from datetime import timedelta
import logging
from functools import wraps
from .models import Voucher, PenukaranVoucher
from authorization.models import Pengguna, Normal

# Setup logging
logger = logging.getLogger(__name__)

# ------- HELPER FUNCTIONS & DEKORATOR SEDERHANA -------

def auth_required(view_func):
    """Memastikan user sudah login sebelum mengakses fungsi"""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if 'user_id' not in request.session:
            messages.error(request, "Akses ditolak. Silakan login terlebih dahulu.")
            logger.warning(f"Unauthorized access attempt to {request.path} from {request.META.get('REMOTE_ADDR')}")
            return redirect('auth:sign_in')
        return view_func(request, *args, **kwargs)
    return wrapper

def get_client_ip(request):
    """Mendapatkan IP address client"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def log_security_event(request, event_type, details):
    """Fungsi sederhana untuk mencatat event keamanan"""
    user_id = request.session.get('user_id', 'anonymous')
    ip = get_client_ip(request)
    logger.warning(f"SECURITY EVENT: {event_type} | User: {user_id} | IP: {ip} | Details: {details}")

def check_throttling(request, action_type, max_attempts=3, timeframe_minutes=60):
    """
    Memeriksa apakah user telah melakukan terlalu banyak percobaan dalam waktu tertentu
    Mengembalikan (throttled, detail) - throttled adalah boolean
    """
    if 'user_id' not in request.session:
        return False, ""
        
    user_id = request.session.get('user_id')
    now = timezone.now()
    timeframe_start = now - timedelta(minutes=timeframe_minutes)
    
    # Cek jumlah aktivitas dalam periode waktu tertentu
    recent_redemptions = PenukaranVoucher.objects.filter(
        pengguna_id=user_id,
        tanggal_penukaran__gte=timeframe_start
    ).count()
    
    if recent_redemptions >= max_attempts:
        details = f"User {user_id} exceeded {action_type} limit: {recent_redemptions} attempts in {timeframe_minutes} minutes"
        return True, details
        
    return False, ""

def check_fraudulent_activity(request, voucher_id, poin_user, jumlah_potongan):
    """Memeriksa kemungkinan aktivitas fraud dalam penukaran voucher"""
    user_id = request.session.get('user_id')
    suspicious = False
    details = []
    
    # 1. Cek jika potongan tidak masuk akal dibanding poin user
    if jumlah_potongan > poin_user * 0.9:  # Jika menggunakan >90% poin sekaligus
        suspicious = True
        details.append(f"High value redemption: {jumlah_potongan}/{poin_user} points")
    
    # 2. Cek frekuensi penukaran (3+ dalam 1 jam = mencurigakan)
    throttled, throttle_details = check_throttling(request, "voucher_redemption", 3, 60)
    if throttled:
        suspicious = True
        details.append(throttle_details)
    
    # 3. Cek pola waktu mencurigakan (jam 1-5 pagi)
    current_hour = timezone.now().hour
    if 1 <= current_hour <= 5:
        suspicious = True
        details.append(f"Unusual transaction time: {current_hour}:00")
    
    if suspicious:
        combined_details = " | ".join(details)
        log_security_event(request, "SUSPICIOUS_REDEMPTION", 
                          f"Voucher: {voucher_id}, Points: {jumlah_potongan}, Issues: {combined_details}")
                          
    return suspicious


# ------- VIEWS UTAMA DENGAN KEAMANAN -------

def daftar_voucher(request):
    """Menampilkan daftar voucher yang tersedia"""
    is_logged_in = 'user_id' in request.session
    
    if is_logged_in:
        user_id = request.session.get('user_id')
        try:
            pengguna = Pengguna.objects.get(id=user_id)
            normal_user = Normal.objects.get(pengguna=pengguna)
            poin = normal_user.poin or 0
            display_name = normal_user.nama or pengguna.email
            
            # Log view voucher jika user login
            logger.info(f"User {user_id} viewed voucher list")
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

@auth_required
def tukar_voucher(request, voucher_id):
    """Menukar voucher dengan poin pengguna - dengan pemeriksaan keamanan"""
    user_id = request.session.get('user_id')
    
    # 1. Limit frequency - cek throttling
    throttled, detail = check_throttling(request, "voucher_redemption")
    if throttled:
        messages.error(request, "Terlalu banyak percobaan penukaran voucher. Silakan coba lagi nanti.")
        return redirect('voucher:daftar_voucher')
    
    # 2. Validasi data pengguna
    try:
        pengguna = Pengguna.objects.get(id=user_id)
        normal_user = Normal.objects.get(pengguna=pengguna)
        poin_user = normal_user.poin or 0
    except (Pengguna.DoesNotExist, Normal.DoesNotExist):
        messages.error(request, "Data pengguna tidak ditemukan")
        log_security_event(request, "INVALID_USER_DATA", f"Failed redemption for voucher:{voucher_id}")
        return redirect('voucher:daftar_voucher')
    
    # 3. Get dan validasi data voucher
    try:
        voucher = get_object_or_404(Voucher, id_voucher=voucher_id)
    except:
        log_security_event(request, "INVALID_VOUCHER", f"Invalid voucher ID: {voucher_id}")
        messages.error(request, "Voucher tidak valid")
        return redirect('voucher:daftar_voucher')
    
    # 4. Cek kecukupan poin
    if poin_user < voucher.jumlah_potongan:
        log_security_event(request, "INSUFFICIENT_POINTS", 
                         f"User:{user_id}, Voucher:{voucher_id}, Points:{poin_user}/{voucher.jumlah_potongan}")
        messages.error(request, f"Poin Anda tidak cukup. Dibutuhkan {voucher.jumlah_potongan} poin")
        return redirect('voucher:daftar_voucher')
    
    # 5. Cek kemungkinan fraud
    if check_fraudulent_activity(request, voucher_id, poin_user, voucher.jumlah_potongan):
        # Masih diizinkan melanjutkan, tapi dicatat sebagai aktivitas mencurigakan
        logger.warning(f"Potential fraudulent activity detected for user {user_id}")
    
    if request.method == 'POST':
        try:
            # 6. Use transaction to ensure data consistency
            with transaction.atomic():
                # Simpan poin awal sebelum penukaran untuk verifikasi
                poin_awal = poin_user
                
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
                
                # 7. Verifikasi data - Integrity check
                normal_user.refresh_from_db()
                if normal_user.poin != poin_awal - voucher.jumlah_potongan:
                    # Point inconsistency detected - possible tampering
                    log_security_event(request, "POINT_INCONSISTENCY", 
                                    f"Expected:{poin_awal-voucher.jumlah_potongan}, Actual:{normal_user.poin}")
                    raise ValueError("Data inconsistency detected")
                
            # 8. Log successful transaction
            logger.info(f"Successful voucher redemption: User {user_id}, Voucher {voucher_id}")
            messages.success(request, f"Berhasil menukar voucher {voucher.nama_voucher}")
            return redirect('voucher:riwayat_penukaran')
            
        except Exception as e:
            logger.error(f"Error redeeming voucher: {str(e)}")
            messages.error(request, "Terjadi kesalahan saat menukar voucher. Silakan coba lagi.")
    
    # Tampilkan halaman konfirmasi
    context = {
        'voucher': voucher,
        'poin_user': poin_user
    }
    return render(request, 'voucher/konfirmasi_tukar.html', context)

@auth_required
def riwayat_penukaran(request):
    """Menampilkan riwayat penukaran voucher pengguna"""
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