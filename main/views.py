from django.db import connection
from django.shortcuts import render
from authorization.models import Pengguna  # Pastikan ini sesuai dengan model yang Anda buat

def landing_page(request):
    # Default values
    is_logged_in = False
    display_name = "Tamu"
    
    # Cek apakah user_id ada di session
    if 'user_id' in request.session:
        user_id = request.session.get('user_id')
        
        # Validasi apakah user masih ada di database
        try:
            # Gunakan model untuk memverifikasi user
            pengguna = Pengguna.objects.get(id=user_id)
            is_logged_in = True
            display_name = request.session.get('display_name', pengguna.email.split('@')[0])
        except Pengguna.DoesNotExist:
            # Jika user tidak ditemukan, hapus session
            if 'user_id' in request.session:
                del request.session['user_id']
            if 'user_email' in request.session:
                del request.session['user_email']
            if 'display_name' in request.session:
                del request.session['display_name']
    
    context = {
        'user_name': display_name,
        'is_logged_in': is_logged_in
    }
    return render(request, 'landingpage.html', context)