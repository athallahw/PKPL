from django.shortcuts import render, redirect
from django.db import connection
from django.contrib.auth import authenticate, login

def sign_up(request):
    if request.method == 'POST':
        # Capture form data
        nama_lengkap = request.POST['nama_lengkap']
        email = request.POST['email']
        password = request.POST['password']
        # You can add more fields from your form here if needed

        # Cek apakah email sudah terdaftar
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT EXISTS(
                    SELECT 1 FROM pengguna WHERE email = %s
                )
                """, [email]
            )
            email_exists = cursor.fetchone()[0]

            if email_exists:
                return render(request, 'sign_up.html', {
                    'error': 'Email sudah terdaftar. Silakan gunakan email lain atau login.'
                })

            # Jika email belum terdaftar, lakukan insert
            cursor.execute(
                """
                INSERT INTO pengguna (email, password)
                VALUES (%s, %s)
                """, [email, password]
            )
        
        # Redirect ke halaman sign in setelah berhasil mendaftar
        return redirect('auth:sign_in')

    return render(request, 'sign_up.html')


def sign_in(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']

        # SQL query to authenticate user by email and password
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, email FROM pengguna 
                WHERE email = %s AND password = %s
                """, [email, password]
            )
            user = cursor.fetchone()

        if user:
            # User exists, simpan data ke session
            request.session['user_id'] = user[0]
            request.session['user_email'] = user[1]
            request.session['display_name'] = user[1].split('@')[0]
            
            return redirect('main:landing_page')
        else:
            return render(request, 'sign_in.html', {'error': 'Email atau password salah'})

    return render(request, 'sign_in.html')
