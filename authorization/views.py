import random
from django.shortcuts import render, redirect
from django.contrib.auth.hashers import make_password, check_password
from django.contrib import messages
from django.http import JsonResponse, HttpResponse
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
from django.http import HttpResponseForbidden
from django.utils.http import url_has_allowed_host_and_scheme
from functools import wraps
from django.core.cache import cache
from django.conf import settings
import re
from django.shortcuts import render, redirect
from django.contrib.auth.hashers import make_password, check_password
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect
from django.utils.crypto import get_random_string
import logging
import time
import pyotp
import qrcode
from io import BytesIO
import base64
from .models import Pengguna, OTPDevice
from authorization.middleware import SecurityMiddleware

SESSION_TIMEOUT = 1800


def rate_limit(key_prefix, limit=5, period=60, block_period=300):
    """
    Rate limiting decorator that can be applied to views
    
    Args:
        key_prefix: Prefix for the cache key (e.g., 'login', 'signup')
        limit: Maximum number of requests allowed in the period
        period: Time period in seconds for the limit
        block_period: Time in seconds to block if limit is exceeded
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            # Get client IP - consider X-Forwarded-For if behind proxy
            ip = get_client_ip(request)
            
            # Create cache keys for this IP and endpoint
            count_key = f"rl:{key_prefix}:{ip}:count"
            block_key = f"rl:{key_prefix}:{ip}:blocked"
            
            # Check if client is blocked
            if cache.get(block_key):
                return HttpResponseForbidden(
                    "Too many attempts. Please try again later."
                )
            
            # Get current request count
            request_count = cache.get(count_key, 0)
            
            # If under limit, increment and proceed
            if request_count < limit:
                # Initialize or increment counter
                if request_count == 0:
                    cache.set(count_key, 1, period)
                else:
                    cache.incr(count_key)
                return view_func(request, *args, **kwargs)
            else:
                # Block the client for a period
                cache.set(block_key, True, block_period)
                logger.warning(f"Rate limit exceeded for {ip} on {key_prefix}")
                return HttpResponseForbidden(
                    "Too many attempts. Please try again later."
                )
        return wrapped_view
    return decorator

def get_client_ip(request):
    """Extract the client IP from request, considering proxy headers"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def validate_password_strength(password):
    """Validate password meets security requirements"""
    errors = []
    
    if len(password) < 10:
        errors.append("Password must be at least 10 characters long")
        
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")
        
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")
        
    if not re.search(r'[0-9]', password):
        errors.append("Password must contain at least one number")
        
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append("Password must contain at least one special character")
        
    return errors

def sanitize_input(input_string):
    """Basic input sanitization"""
    if input_string is None:
        return ''
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[<>"\';]', '', input_string)
    return sanitized

def validate_redirect_url(url, allowed_hosts=None):
    """Validate that a URL is safe for redirection"""
    if allowed_hosts is None:
        allowed_hosts = [settings.ALLOWED_HOSTS[0] if settings.ALLOWED_HOSTS else 'localhost']
    
    # Use the current Django function instead of the deprecated is_safe_url
    return url_has_allowed_host_and_scheme(
        url=url,
        allowed_hosts=allowed_hosts,
        require_https=settings.SESSION_COOKIE_SECURE
    )

# Setup logging for audit trail
logger = logging.getLogger('auth_audit')
logger.setLevel(logging.INFO)

@rate_limit('sign_up', limit=5, period=300)  # 5 attempts in 5 minutes
@csrf_protect
def sign_up(request):
    if request.method == 'POST':
        # Sanitize inputs
        nama_lengkap = sanitize_input(request.POST.get('nama_lengkap', '')).strip()
        email = sanitize_input(request.POST.get('email', '')).strip().lower()
        password = request.POST.get('password', '')
        
        # Validate input data
        errors = {}
        if not nama_lengkap:
            errors['nama_lengkap'] = 'Nama lengkap harus diisi'
        
        if not email:
            errors['email'] = 'Email harus diisi'
        elif not is_valid_email(email):
            errors['email'] = 'Format email tidak valid'
        
        # Enhanced password validation
        password_errors = validate_password_strength(password)
        if password_errors:
            errors['password'] = password_errors[0]  # Show first error
        
        if errors:
            return render(request, 'sign_up.html', {'errors': errors})
            
        # Check if email already exists
        if Pengguna.objects.filter(email=email).exists():
            # Don't leak existence of account - delay response
            time.sleep(1)  # Add random delay to prevent timing attacks
            logger.info(f"Registration attempt with existing email: {email}")
            return render(request, 'sign_up.html', {
                'error': 'Email sudah terdaftar. Silakan gunakan email lain atau login.'
            })
        
        # Store registration data in session with expiry
        request.session['signup_data'] = {
            'nama_lengkap': nama_lengkap,
            'email': email,
            'password': make_password(password),
            'timestamp': time.time()  # Add timestamp for expiry check
        }
        
        # Set session expiry for security
        request.session.set_expiry(600)  # 10 minutes
        
        # Redirect to OTP setup
        return redirect('auth:setup_new_account')
            
    return render(request, 'sign_up.html')

@rate_limit('sign_in', limit=5, period=300)  # 5 attempts in 5 minutes
@csrf_protect
def sign_in(request):
    if request.method == 'POST':
        email = sanitize_input(request.POST.get('email', '')).strip().lower()
        password = request.POST.get('password', '')
        
        # Add delay to prevent timing attacks
        time.sleep(0.5 + (random.random() * 0.5))  # 0.5-1.0 second delay
        
        try:
            pengguna = Pengguna.objects.get(email=email)
            
            # Verify password
            if check_password(password, pengguna.password):
                # Check for account lockout
                if is_account_locked(pengguna.id):
                    logger.warning(f"Login attempt on locked account: {email}")
                    return render(request, 'sign_in.html', 
                                  {'error': 'Account temporarily locked. Please try again later.'})
                
                # Store user information in session temporarily
                request.session['temp_user_id'] = pengguna.id
                request.session['temp_login_email'] = email
                request.session['login_timestamp'] = time.time()
                request.session.set_expiry(300)  # 5 minute expiry for temp session
                
                # Reset failed login attempts
                reset_failed_login_attempts(pengguna.id)
                
                # Check if user has OTP set up
                try:
                    OTPDevice.objects.get(pengguna=pengguna)
                    return redirect('auth:verify_otp')
                except OTPDevice.DoesNotExist:
                    return redirect('auth:setup_otp')
            else:
                # Invalid password
                increment_failed_login_attempts(pengguna.id)
                return render(request, 'sign_in.html', {'error': 'Email atau password salah'})
                
        except Pengguna.DoesNotExist:
            # Don't leak account existence - generic message
            return render(request, 'sign_in.html', {'error': 'Email atau password salah'})
            
    # Set secure headers for login page
    response = render(request, 'sign_in.html')
    add_security_headers(response)
    return response

def is_account_locked(user_id):
    """Check if account is locked due to failed attempts"""
    key = f"account_lock:{user_id}"
    return cache.get(key, False)

def increment_failed_login_attempts(user_id):
    """Track failed login attempts and lock account if threshold reached"""
    key = f"failed_login:{user_id}"
    attempts = cache.get(key, 0)
    attempts += 1
    
    # Lock account after 5 failed attempts
    if attempts >= 5:
        logger.warning(f"Account locked due to failed login attempts: user_id={user_id}")
        cache.set(f"account_lock:{user_id}", True, 1800)  # Lock for 30 minutes
        # Reset the counter
        cache.delete(key)
    else:
        # Set with expiry of 30 minutes
        cache.set(key, attempts, 1800)

def reset_failed_login_attempts(user_id):
    """Reset failed login attempts counter on successful login"""
    cache.delete(f"failed_login:{user_id}")

def increment_failed_otp_attempts(user_id):
    """Track failed OTP attempts"""
    key = f"failed_otp:{user_id}"
    attempts = cache.get(key, 0)
    attempts += 1
    
    # Lock account after 3 failed OTP attempts
    if attempts >= 3:
        logger.warning(f"Account locked due to failed OTP attempts: user_id={user_id}")
        cache.set(f"account_lock:{user_id}", True, 1800)  # Lock for 30 minutes
        cache.delete(key)
    else:
        cache.set(key, attempts, 1800)

def clear_login_session(request):
    """Clear sensitive session data"""
    keys = ['temp_user_id', 'temp_login_email', 'login_timestamp', 'next_url']
    for key in keys:
        if key in request.session:
            del request.session[key]

def setup_secure_session(request, pengguna):
    """Set up secure session after successful authentication"""
    # Clear temporary login data
    clear_login_session(request)
    
    # Set authenticated session data
    request.session['user_id'] = pengguna.id
    request.session['user_email'] = pengguna.email
    request.session['authenticated_at'] = time.time()
    
    # Set session to expire after 30 minutes of inactivity
    request.session.set_expiry(1800)
    
    # Check if user is admin
    try:
        Admin.objects.get(pengguna=pengguna)
        request.session['is_admin'] = True
    except Admin.DoesNotExist:
        request.session['is_admin'] = False

def add_security_headers(response):
    """Add security headers to response"""
    # Content Security Policy
    response['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none';"
    
    # Prevent MIME sniffing
    response['X-Content-Type-Options'] = 'nosniff'
    
    # XSS protection
    response['X-XSS-Protection'] = '1; mode=block'
    
    # Referrer policy
    response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Frame options
    response['X-Frame-Options'] = 'DENY'
    
    return response



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

@rate_limit('verify_otp', limit=3, period=300)  # 3 attempts in 5 minutes
def verify_otp(request):
    email = request.session.get('temp_login_email')
    
    # Session timeout check
    login_timestamp = request.session.get('login_timestamp')
    if not email or not login_timestamp or (time.time() - login_timestamp > 300):
        # Session expired or invalid
        messages.warning(request, 'Your session has expired. Please log in again.')
        clear_login_session(request)
        return redirect('auth:sign_in')

    if request.method == 'POST':
        otp_code = sanitize_input(request.POST.get('otp_code', ''))
        
        try:
            pengguna = Pengguna.objects.get(email=email)
            otp_device = OTPDevice.objects.get(pengguna=pengguna)
            totp = pyotp.TOTP(otp_device.secret_key)

            if totp.verify(otp_code):
                # Complete login and establish secure session
                setup_secure_session(request, pengguna)
                messages.success(request, 'Login successful!')
                
                # Log successful login
                logger.info(f"Successful login with 2FA: {email}")
                
                # Redirect to requested URL or default
                next_url = request.session.get('next_url', 'main:landing_page')
                if not validate_redirect_url(next_url):
                    next_url = 'main:landing_page'
                
                return redirect(next_url)
            else:
                messages.warning(request, 'Invalid verification code. Please try again.')
                
                # Increment failed OTP attempts
                increment_failed_otp_attempts(pengguna.id)
                
                return render(request, 'verify_otp.html', {'email': email})
                
        except Exception as e:
            logger.error(f"OTP verification error: {str(e)}")
            messages.warning(request, 'An error occurred. Please try again.')
            return redirect('auth:sign_in')

    response = render(request, 'verify_otp.html', {'email': email})
    add_security_headers(response)
    return response

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
    
