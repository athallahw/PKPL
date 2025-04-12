from django.shortcuts import render, redirect
from django.contrib.auth.hashers import make_password, check_password
from django.contrib import messages
from .models import Pengguna, Normal, Admin

def sign_up(request):
    if request.method == 'POST':
        nama_lengkap = request.POST['nama_lengkap']
        email = request.POST['email']
        password = request.POST['password']
        
        if Pengguna.objects.filter(email=email).exists():
            return render(request, 'sign_up.html', {
                'error': 'Email sudah terdaftar. Silakan gunakan email lain atau login.'
            })
        
        pengguna = Pengguna.objects.create(
            email=email,
            password=make_password(password)  
        )
        
        
        nama_parts = nama_lengkap.split(' ', 1)
        nama_depan = nama_parts[0]
        nama_belakang = nama_parts[1] if len(nama_parts) > 1 else ''
        
        Normal.objects.create(
            pengguna=pengguna,
            nama_depan=nama_depan,
            nama_belakang=nama_belakang,
            nama=nama_lengkap,
            poin=0  
        )
        
        messages.success(request, 'Akun berhasil dibuat! Silakan login.')
        return redirect('auth:sign_in')

    return render(request, 'sign_up.html')


def sign_in(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']

        try:
            pengguna = Pengguna.objects.get(email=email)
            
            if check_password(password, pengguna.password):
                request.session['user_id'] = pengguna.id
                request.session['user_email'] = pengguna.email
                request.session['display_name'] = email.split('@')[0]
                
                try:
                    admin = Admin.objects.get(pengguna=pengguna)
                    request.session['is_admin'] = True
                except Admin.DoesNotExist:
                    request.session['is_admin'] = False
                    
                    try:
                        normal_user = Normal.objects.get(pengguna=pengguna)
                        if normal_user.nama:
                            request.session['display_name'] = normal_user.nama
                    except Normal.DoesNotExist:
                        pass
                
                return redirect('main:landing_page')
            else:
                return render(request, 'sign_in.html', {'error': 'Email atau password salah'})
                
        except Pengguna.DoesNotExist:
            return render(request, 'sign_in.html', {'error': 'Email atau password salah'})

    return render(request, 'sign_in.html')


def logout(request):
    for key in list(request.session.keys()):
        del request.session[key]
    
    return redirect('auth:sign_in')