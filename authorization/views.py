from django.shortcuts import render, redirect
from django.contrib.auth.hashers import make_password, check_password
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect
from django.utils.crypto import get_random_string
import logging
import time
from .models import Pengguna, Normal, Admin
import pyotp
import qrcode
from io import BytesIO
import base64
from .models import Pengguna, OTPDevice



# Setup logging for audit trail
logger = logging.getLogger('auth_audit')
logger.setLevel(logging.INFO)

# Session timeout (30 minutes)
SESSION_TIMEOUT = 1800

@csrf_protect
def sign_up(request):
    if request.method == 'POST':
        # Input validation - prevent tampering/injection
        nama_lengkap = request.POST.get('nama_lengkap', '').strip()
        email = request.POST.get('email', '').strip().lower()
        password = request.POST.get('password', '')
        
        # Validate input data
        errors = {}
        if not nama_lengkap:
            errors['nama_lengkap'] = 'Nama lengkap harus diisi'
        
        if not email:
            errors['email'] = 'Email harus diisi'
        elif not is_valid_email(email):
            errors['email'] = 'Format email tidak valid'
            
        if not password:
            errors['password'] = 'Password harus diisi'
        elif len(password) < 8:
            errors['password'] = 'Password minimal 8 karakter'
        
        if errors:
            return render(request, 'sign_up.html', {'errors': errors})
            
        # Check if email already exists
        if Pengguna.objects.filter(email=email).exists():
            logger.info(f"Registration attempt with existing email: {email}")
            return render(request, 'sign_up.html', {
                'error': 'Email sudah terdaftar. Silakan gunakan email lain atau login.'
            })
        
        # Simulate OTP verification for now
        # In a production environment, you would implement actual OTP
        # For the prototype, we'll proceed directly to account creation
        
        try:
            # Create user with hashed password
            pengguna = Pengguna.objects.create(
                email=email,
                password=make_password(password)
            )
            
            # Parse name
            nama_parts = nama_lengkap.split(' ', 1)
            nama_depan = nama_parts[0]
            nama_belakang = nama_parts[1] if len(nama_parts) > 1 else ''
            
            # Create user profile with default points
            Normal.objects.create(
                pengguna=pengguna,
                nama_depan=nama_depan,
                nama_belakang=nama_belakang,
                nama=nama_lengkap,
                poin=0
            )
            
            # Log successful registration
            logger.info(f"User registered successfully: {email}")
            
            messages.success(request, 'Akun berhasil dibuat! Silakan login.')
            return redirect('auth:sign_in')
            
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            return render(request, 'sign_up.html', {
                'error': 'Terjadi kesalahan saat mendaftarkan akun.'
            })
            
    return render(request, 'sign_up.html')

@csrf_protect
def sign_in(request):
    if request.method == 'POST':
        email = request.POST.get('email', '').strip().lower()
        password = request.POST.get('password', '')
        
        try:
            pengguna = Pengguna.objects.get(email=email)
            
            # Verify password
            if check_password(password, pengguna.password):
                # Store email in session temporarily
                request.session['temp_login_email'] = email
                
                # Redirect to OTP verification
                return redirect('auth:verify_otp')
            else:
                # Invalid password
                return render(request, 'sign_in.html', {'error': 'Email atau password salah'})
                
        except Pengguna.DoesNotExist:
            return render(request, 'sign_in.html', {'error': 'Email atau password salah'})
            
    return render(request, 'sign_in.html')

def logout(request):
    # Log the logout event
    if 'user_email' in request.session:
        logger.info(f"User logged out: {request.session['user_email']}")
    
    # Clear all session data
    for key in list(request.session.keys()):
        del request.session[key]
    
    # Redirect to login page
    return redirect('auth:sign_in')

# Utility Functions
def is_valid_email(email):
    """Simple email validation"""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# Authorization check helper
def has_permission(request, required_permission):
    """
    Simple permission check based on admin status
    In a full implementation, this would check against a permissions table
    """
    if required_permission == 'admin_access':
        return request.session.get('is_admin', False)
    elif required_permission == 'user_access':
        return 'user_id' in request.session
    else:
        return False
    

def generate_otp_secret():
    return pyotp.random_base32()

from django.shortcuts import render, redirect
from django.contrib.auth.hashers import make_password, check_password
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect
from django.utils.crypto import get_random_string
import logging
import time
from .models import Pengguna, Normal, Admin
import pyotp
import qrcode
from io import BytesIO
import base64
from .models import Pengguna, OTPDevice



# Setup logging for audit trail
logger = logging.getLogger('auth_audit')
logger.setLevel(logging.INFO)

# Session timeout (30 minutes)
SESSION_TIMEOUT = 1800

@csrf_protect
def sign_up(request):
    if request.method == 'POST':
        # Input validation - prevent tampering/injection
        nama_lengkap = request.POST.get('nama_lengkap', '').strip()
        email = request.POST.get('email', '').strip().lower()
        password = request.POST.get('password', '')
        
        # Validate input data
        errors = {}
        if not nama_lengkap:
            errors['nama_lengkap'] = 'Nama lengkap harus diisi'
        
        if not email:
            errors['email'] = 'Email harus diisi'
        elif not is_valid_email(email):
            errors['email'] = 'Format email tidak valid'
            
        if not password:
            errors['password'] = 'Password harus diisi'
        elif len(password) < 8:
            errors['password'] = 'Password minimal 8 karakter'
        
        if errors:
            return render(request, 'sign_up.html', {'errors': errors})
            
        # Check if email already exists
        if Pengguna.objects.filter(email=email).exists():
            logger.info(f"Registration attempt with existing email: {email}")
            return render(request, 'sign_up.html', {
                'error': 'Email sudah terdaftar. Silakan gunakan email lain atau login.'
            })
        
        # Simulate OTP verification for now
        # In a production environment, you would implement actual OTP
        # For the prototype, we'll proceed directly to account creation
        
        try:
            # Create user with hashed password
            pengguna = Pengguna.objects.create(
                email=email,
                password=make_password(password)
            )
            
            # Parse name
            nama_parts = nama_lengkap.split(' ', 1)
            nama_depan = nama_parts[0]
            nama_belakang = nama_parts[1] if len(nama_parts) > 1 else ''
            
            # Create user profile with default points
            Normal.objects.create(
                pengguna=pengguna,
                nama_depan=nama_depan,
                nama_belakang=nama_belakang,
                nama=nama_lengkap,
                poin=0
            )
            
            # Log successful registration
            logger.info(f"User registered successfully: {email}")
            
            messages.success(request, 'Akun berhasil dibuat! Silakan login.')
            return redirect('auth:sign_in')
            
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            return render(request, 'sign_up.html', {
                'error': 'Terjadi kesalahan saat mendaftarkan akun.'
            })
            
    return render(request, 'sign_up.html')

@csrf_protect
def sign_in(request):
    if request.method == 'POST':
        email = request.POST.get('email', '').strip().lower()
        password = request.POST.get('password', '')
        
        try:
            pengguna = Pengguna.objects.get(email=email)
            
            # Verify password
            if check_password(password, pengguna.password):
                # Store user information in session temporarily
                request.session['temp_user_id'] = pengguna.id
                request.session['temp_login_email'] = email
                
                # Check if user has OTP set up
                try:
                    otp_device = OTPDevice.objects.get(pengguna=pengguna)
                    # User has OTP device, redirect to verification
                    return redirect('auth:verify_otp')
                except OTPDevice.DoesNotExist:
                    # User doesn't have OTP set up yet, redirect to setup
                    return redirect('auth:setup_otp')
            else:
                # Invalid password
                return render(request, 'sign_in.html', {'error': 'Email atau password salah'})
                
        except Pengguna.DoesNotExist:
            return render(request, 'sign_in.html', {'error': 'Email atau password salah'})
            
    return render(request, 'sign_in.html')
def logout(request):
    # Log the logout event
    if 'user_email' in request.session:
        logger.info(f"User logged out: {request.session['user_email']}")
    
    # Clear all session data
    for key in list(request.session.keys()):
        del request.session[key]
    
    # Redirect to login page
    return redirect('auth:sign_in')

# Utility Functions
def is_valid_email(email):
    """Simple email validation"""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# Authorization check helper
def has_permission(request, required_permission):
    """
    Simple permission check based on admin status
    In a full implementation, this would check against a permissions table
    """
    if required_permission == 'admin_access':
        return request.session.get('is_admin', False)
    elif required_permission == 'user_access':
        return 'user_id' in request.session
    else:
        return False
    

def generate_otp_secret():
    return pyotp.random_base32()

def setup_otp(request):
    """View to set up OTP for a user"""
    # Check for either permanent or temporary user ID
    user_id = request.session.get('user_id') or request.session.get('temp_user_id')
    
    if not user_id:
        # If no user ID is found, redirect to sign in
        return redirect('auth:sign_in')
    
    try:
        # Use the user ID we found
        pengguna = Pengguna.objects.get(id=user_id)
        
        try:
            # Make sure the OTPDevice model is properly migrated
            # Create or update OTP device
            otp_device, created = OTPDevice.objects.update_or_create(
                pengguna=pengguna,
                defaults={'secret_key': generate_otp_secret()}
            )
            
            # Generate TOTP object
            totp = pyotp.TOTP(otp_device.secret_key)
            
            # Create provisioning URI for QR code
            provisioning_uri = totp.provisioning_uri(
                name=pengguna.email,
                issuer_name="PKPL Health Tracker"
            )
            
            # Generate QR code
            qr = qrcode.make(provisioning_uri)
            buffered = BytesIO()
            qr.save(buffered, format="PNG")
            qr_code_img = base64.b64encode(buffered.getvalue()).decode()
            
            return render(request, 'setup_otp.html', {
                'qr_code': qr_code_img,
                'secret_key': otp_device.secret_key,
                'email': pengguna.email
            })
            
        except Exception as e:
            # Log any errors during OTP setup
            print(f"Error setting up OTP: {str(e)}")
            messages.error(request, f"Error setting up OTP: {str(e)}")
            # Always return a response
            return render(request, 'error.html', {
                'error_message': 'Could not set up OTP. Please try again later.'
            })
            
    except Pengguna.DoesNotExist:
        return redirect('auth:sign_in')
    
    # Add a fallback return statement to ensure a response is always returned
    return redirect('auth:sign_in')

def verify_otp(request):
    """View to verify OTP during login"""
    if request.method == 'POST':
        otp_code = request.POST.get('otp_code')
        email = request.POST.get('email')
        
        try:
            pengguna = Pengguna.objects.get(email=email)
            otp_device = OTPDevice.objects.get(pengguna=pengguna)
            
            # Initialize TOTP with user's secret
            totp = pyotp.TOTP(otp_device.secret_key)
            
            # Verify OTP
            if totp.verify(otp_code):
                # OTP is valid, complete login process
                request.session['user_id'] = pengguna.id
                request.session['user_email'] = pengguna.email
                
                # Set other session data as needed
                try:
                    admin = Admin.objects.get(pengguna=pengguna)
                    request.session['is_admin'] = True
                except Admin.DoesNotExist:
                    request.session['is_admin'] = False
                    
                return redirect('main:landing_page')
            else:
                # Invalid OTP
                return render(request, 'verify_otp.html', {
                    'error': 'Kode OTP tidak valid',
                    'email': email
                })
                
        except (Pengguna.DoesNotExist, OTPDevice.DoesNotExist):
            return redirect('auth:sign_in')
            
    return render(request, 'verify_otp.html')

def verify_otp(request):
    """View to verify OTP during login"""
    if request.method == 'POST':
        otp_code = request.POST.get('otp_code')
        email = request.session.get('temp_login_email')
        
        if not email:
            email = request.POST.get('email')
        
        try:
            pengguna = Pengguna.objects.get(email=email)
            otp_device = OTPDevice.objects.get(pengguna=pengguna)
            
            # Initialize TOTP with user's secret
            totp = pyotp.TOTP(otp_device.secret_key)
            
            # Verify OTP
            if totp.verify(otp_code):
                # OTP is valid, complete login process
                request.session['user_id'] = pengguna.id
                request.session['user_email'] = pengguna.email
                
                # Clean up temporary session data
                if 'temp_user_id' in request.session:
                    del request.session['temp_user_id']
                if 'temp_login_email' in request.session:
                    del request.session['temp_login_email']
                
                # Set other session data as needed
                try:
                    admin = Admin.objects.get(pengguna=pengguna)
                    request.session['is_admin'] = True
                except Admin.DoesNotExist:
                    request.session['is_admin'] = False
                    
                return redirect('main:landing_page')
            else:
                # Invalid OTP
                return render(request, 'verify_otp.html', {
                    'error': 'Kode OTP tidak valid',
                    'email': email
                })
                
        except (Pengguna.DoesNotExist, OTPDevice.DoesNotExist):
            return redirect('auth:sign_in')
    
    # GET request - show the form
    email = request.session.get('temp_login_email', '')
    return render(request, 'verify_otp.html', {'email': email})