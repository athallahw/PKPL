from django.shortcuts import render, redirect
from django.contrib.auth.hashers import make_password, check_password
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect
from django.utils.crypto import get_random_string
import logging
import time
from .models import AppIcon, Pengguna, Normal, Admin
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
        
        # Instead of creating user immediately, store registration data in session
        request.session['signup_data'] = {
            'nama_lengkap': nama_lengkap,
            'email': email,
            'password': make_password(password)
        }
        
        # Redirect to OTP setup for new account
        return redirect('auth:setup_new_account')
            
    return render(request, 'sign_up.html')

def setup_new_account(request):
    """Handle OTP setup for new accounts during registration"""
    # Check if we have registration data in session
    signup_data = request.session.get('signup_data')
    
    if not signup_data:
        messages.warning(request, 'Please complete the registration form first.')
        return redirect('auth:sign_up')
    
    email = signup_data.get('email')
    
    if request.method == 'POST':
        otp_code = request.POST.get('otp_code')
        
        try:
            # Verify OTP
            temp_secret = request.session.get('temp_otp_secret')
            if not temp_secret:
                messages.error(request, 'Your session has expired. Please try registering again.')
                return redirect('auth:sign_up')
                
            totp = pyotp.TOTP(temp_secret)
            
            if totp.verify(otp_code):
                # OTP verified, now create the actual user account
                try:
                    # Create the user
                    pengguna = Pengguna.objects.create(
                        email=signup_data['email'],
                        password=signup_data['password']  # Already hashed in sign_up
                    )
                    
                    # Parse name
                    nama_lengkap = signup_data['nama_lengkap']
                    nama_parts = nama_lengkap.split(' ', 1)
                    nama_depan = nama_parts[0]
                    nama_belakang = nama_parts[1] if len(nama_parts) > 1 else ''
                    
                    # Create user profile
                    Normal.objects.create(
                        pengguna=pengguna,
                        nama_depan=nama_depan,
                        nama_belakang=nama_belakang,
                        nama=nama_lengkap,
                        poin=0
                    )
                    
                    # Create OTP device with the verified secret
                    OTPDevice.objects.create(
                        pengguna=pengguna,
                        secret_key=temp_secret
                    )
                    
                    # Clean up session
                    if 'signup_data' in request.session:
                        del request.session['signup_data']
                    if 'temp_otp_secret' in request.session:
                        del request.session['temp_otp_secret']
                    
                    # Log the user in
                    request.session['user_id'] = pengguna.id
                    request.session['user_email'] = pengguna.email
                    
                    messages.success(request, 'Your account has been created and 2FA has been set up successfully!')
                    return redirect('main:landing_page')
                
                except Exception as e:
                    logger.error(f"Error creating account: {str(e)}")
                    messages.error(request, 'An error occurred while creating your account. Please try again.')
                    return redirect('auth:sign_up')
            else:
                # Invalid OTP
                messages.warning(request, 'The verification code you entered is incorrect. Please try again.')
                # Regenerate QR code and show the form again
                return render(request, 'setup_new_account.html', {
                    'email': email,
                    'qr_code': get_qr_code(temp_secret, email),
                    'secret_key': temp_secret
                })
        except Exception as e:
            logger.error(f"OTP verification error: {str(e)}")
            messages.error(request, 'An error occurred during verification. Please try again.')
            return redirect('auth:sign_up')
            
    else:  # GET request - show the OTP setup form
        # Generate new OTP secret for registration
        secret_key = generate_otp_secret()
        request.session['temp_otp_secret'] = secret_key
        
        # Generate QR code
        qr_code_img = get_qr_code(secret_key, email)
        
        return render(request, 'setup_new_account.html', {
            'qr_code': qr_code_img,
            'secret_key': secret_key,
            'email': email
        })

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
    email = request.session.get('temp_login_email') or request.session.get('user_email')
    user_id = request.session.get('temp_user_id')

    app_icons = AppIcon.objects.all()

    if not email:
        return redirect('auth:sign_in')

    if request.method == 'POST':
        otp_code = request.POST.get('otp_code')

        try:
            pengguna = Pengguna.objects.get(email=email)
            otp_device = OTPDevice.objects.get(pengguna=pengguna)
            totp = pyotp.TOTP(otp_device.secret_key)

            if totp.verify(otp_code):
                # OTP is valid, complete setup process
                request.session['user_id'] = pengguna.id
                request.session['user_email'] = pengguna.email
                messages.success(request, 'Two-factor authentication has been successfully activated.')

                if request.session.get('temp_user_id'):
                    del request.session['temp_user_id']
                    del request.session['temp_login_email']
                return redirect('main:landing_page')
            else:
                # User-friendly message for invalid OTP
                messages.warning(request, 'The verification code you entered is incorrect. Please try again.')
                return render(request, 'setup_otp.html', {
                    'email': email,
                    # Re-generate QR code if needed
                    'qr_code': get_qr_code(otp_device.secret_key, email),
                    'secret_key': otp_device.secret_key,
                    'app_icons': app_icons,
                    
                })
        except (Pengguna.DoesNotExist, OTPDevice.DoesNotExist):
            # Log the actual error for developers
            logger.error(f"Error during OTP verification: User or OTP device not found for email {email}")
            # User-friendly message
            messages.warning(request, 'We encountered an issue with your account. Please try signing in again.')
            return redirect('auth:sign_in')
        except Exception as e:
            # Log any unexpected errors
            logger.error(f"Unexpected error during OTP verification: {str(e)}")
            messages.warning(request, 'An unexpected error occurred. Please try again later.')
            return redirect('auth:sign_in')

    elif request.method == 'GET':
        temp_user_id = user_id and user_id in request.session

        if not temp_user_id:
            try:
                pengguna = Pengguna.objects.get(email=email)
                otp_device = OTPDevice.objects.get(pengguna=pengguna)
                messages.info(request, 'Two-factor authentication is already activated.')
                return redirect('auth:sign_in')
            except (Pengguna.DoesNotExist, OTPDevice.DoesNotExist):
                return redirect('auth:sign_in')

        try:
            pengguna = Pengguna.objects.get(id=user_id)

            otp_device, created = OTPDevice.objects.get_or_create(pengguna=pengguna)
            if created:
                secret_key = generate_otp_secret()
                otp_device.secret_key = secret_key
                otp_device.save()
            else:
                secret_key = otp_device.secret_key

            # Generate QR code
            qr_code_img = get_qr_code(secret_key, pengguna.email)

            return render(request, 'setup_otp.html', {
                'qr_code': qr_code_img, 
                'secret_key': secret_key, 
                'email': pengguna.email,
                'app_icons': app_icons,

            })
        except Exception as e:
            # Log the actual error
            logger.error(f"Error generating OTP setup: {str(e)}")
            # Generic message to user
            messages.warning(request, 'We encountered an issue setting up two-factor authentication. Please try again.')
            return redirect('auth:sign_in')


def verify_otp(request):
    email = request.session.get('temp_login_email') or request.session.get('user_email')

    if request.method == 'POST':
        otp_code = request.POST.get('otp_code')

        try:
            pengguna = Pengguna.objects.get(email=email)
            otp_device = OTPDevice.objects.get(pengguna=pengguna)
            totp = pyotp.TOTP(otp_device.secret_key)

            if totp.verify(otp_code):
                request.session['user_id'] = pengguna.id
                request.session['user_email'] = pengguna.email
                messages.success(request, 'Login successful!')
                
                if 'temp_login_email' in request.session:
                    del request.session['temp_login_email']

                try:
                    admin = Admin.objects.get(pengguna=pengguna)
                    request.session['is_admin'] = True
                except Admin.DoesNotExist:
                    request.session['is_admin'] = False
                return redirect('main:landing_page')
            else:
                messages.warning(request, 'The verification code you entered is incorrect. Please try again.')
                return render(request, 'verify_otp.html', {'email': email})
        except (Pengguna.DoesNotExist, OTPDevice.DoesNotExist):
            # Log the actual error
            logger.error(f"Error during OTP verification: User or OTP device not found for email {email}")
            messages.warning(request, 'We encountered an issue with your account. Please try signing in again.')
            return redirect('auth:sign_in')
        except Exception as e:
            # Log any unexpected errors
            logger.error(f"Unexpected error during OTP verification: {str(e)}")
            messages.warning(request, 'An unexpected error occurred. Please try again later.')
            return redirect('auth:sign_in')

    return render(request, 'verify_otp.html', {'email': email})


# Helper function to generate QR code
def get_qr_code(secret_key, email):
    try:
        totp = pyotp.TOTP(secret_key)
        provisioning_uri = totp.provisioning_uri(name=email, issuer_name="PKPL Health Tracker")
        qr = qrcode.make(provisioning_uri)
        buffered = BytesIO()
        qr.save(buffered, format="PNG")
        return base64.b64encode(buffered.getvalue()).decode()
    except Exception as e:
        logger.error(f"Error generating QR code: {str(e)}")
        # Return empty string or a default image if error occurs
        return ""