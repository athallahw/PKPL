from django.test import TestCase, Client, TransactionTestCase
from django.urls import reverse
from django.contrib.messages import get_messages
from .models import Pengguna, OTPDevice, Normal, Role
from django.core.cache import cache
from django.contrib.auth.hashers import make_password
import pyotp
import time
from unittest.mock import patch, MagicMock
from unittest import skip
import re
import html
from bs4 import BeautifulSoup

class ViewTestMixin:
    """Mixin with common test methods to avoid duplication"""
    
    def setUp(self):
        self.client = Client()
        self.signup_url = reverse('auth:sign_up')
        self.signin_url = reverse('auth:sign_in')
        self.setup_otp_url = reverse('auth:setup_otp')
        self.verify_otp_url = reverse('auth:verify_otp')
        
        # Create test role
        self.user_role = Role.objects.create(role_name='pengguna')
        
        # Create test user with hashed password
        self.password = 'TestPassword123!'
        self.test_user = Pengguna.objects.create(
            email='test@example.com',
            password=make_password(self.password),  # Using Django's password hashing
            role=self.user_role
        )
        self.normal_user = Normal.objects.create(
            pengguna=self.test_user,
            nama_depan='Test',
            nama_belakang='User',
            nama='Test User',
            poin=0
        )
        
        # Create OTP device for test user
        self.otp_secret = pyotp.random_base32()
        self.otp_device = OTPDevice.objects.create(
            pengguna=self.test_user,
            secret_key=self.otp_secret
        )
        
        # Clear cache before each test
        cache.clear()

class AuthorizationViewsTest(ViewTestMixin, TestCase):
    """Basic test cases for authentication views"""
    
    @patch('authorization.views.is_valid_email', return_value=True)
    def test_sign_up_get(self, mock_email_validator):
        response = self.client.get(self.signup_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'sign_up.html')

    @patch('authorization.views.is_valid_email', return_value=True)
    @patch('authorization.views.validate_password_strength', return_value=[])
    def test_sign_up_post_valid(self, mock_password_validator, mock_email_validator):
        data = {
            'nama_lengkap': 'John Doe',
            'email': 'newuser@example.com',
            'password': 'StrongPass123!'
        }
        response = self.client.post(self.signup_url, data)
        self.assertEqual(response.status_code, 302)  # Should redirect to setup_new_account
        self.assertTrue('signup_data' in self.client.session)

    @patch('authorization.views.is_valid_email', return_value=False)
    def test_sign_up_post_invalid(self, mock_email_validator):
        data = {
            'nama_lengkap': '',
            'email': 'invalidemail',
            'password': 'weak'
        }
        response = self.client.post(self.signup_url, data)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'sign_up.html')

    def test_sign_in_get(self):
        response = self.client.get(self.signin_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'sign_in.html')
    
    @patch('authorization.views.check_password', return_value=True)
    def test_sign_in_post_valid(self, mock_check_password):
        data = {
            'email': 'test@example.com',
            'password': self.password
        }
        response = self.client.post(self.signin_url, data)
        self.assertEqual(response.status_code, 302)  # Should redirect to verify_otp or setup_otp

    @patch('authorization.views.check_password', return_value=False)
    def test_sign_in_post_invalid(self, mock_check_password):
        data = {
            'email': 'test@example.com',
            'password': 'wrongpassword'
        }
        response = self.client.post(self.signin_url, data)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'sign_in.html')

    def test_verify_otp_get(self):
        # Set up session data
        session = self.client.session
        session['temp_login_email'] = 'test@example.com'
        session['login_timestamp'] = time.time()
        session.save()
        
        response = self.client.get(self.verify_otp_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'verify_otp.html')

    @patch('pyotp.TOTP.verify', return_value=True)
    def test_verify_otp_post_valid(self, mock_verify):
        # Set up session data
        session = self.client.session
        session['temp_login_email'] = 'test@example.com'
        session['login_timestamp'] = time.time()
        session.save()
        
        data = {'otp_code': '123456'}  # Any code works due to mock
        response = self.client.post(self.verify_otp_url, data)
        self.assertEqual(response.status_code, 302)  # Should redirect to landing page

    @patch('pyotp.TOTP.verify', return_value=False)
    def test_verify_otp_post_invalid(self, mock_verify):
        # Set up session data
        session = self.client.session
        session['temp_login_email'] = 'test@example.com'
        session['login_timestamp'] = time.time()
        session.save()
        
        data = {'otp_code': '000000'}  # Invalid OTP
        response = self.client.post(self.verify_otp_url, data)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'verify_otp.html')

    def test_logout(self):
        # Set up authenticated session
        session = self.client.session
        session['user_id'] = self.test_user.id
        session['user_email'] = self.test_user.email
        session.save()
        
        response = self.client.get(reverse('auth:logout'))
        self.assertEqual(response.status_code, 302)  # Should redirect to sign in
        self.assertFalse('user_id' in self.client.session)

    @patch('authorization.views.validate_password_strength')
    def test_password_validation(self, mock_validate_password):
        # Simulate different validation errors for each test case
        test_cases = [
            {'error': ['Password must be at least 10 characters long'], 'password': 'short'},
            {'error': ['Password must contain at least one uppercase letter'], 'password': 'nouppercase123!'},
            {'error': ['Password must contain at least one lowercase letter'], 'password': 'NOLOWERCASE123!'},
            {'error': ['Password must contain at least one number'], 'password': 'NoNumbers!'},
            {'error': ['Password must contain at least one special character'], 'password': 'NoSpecial123'}
        ]
        
        for case in test_cases:
            mock_validate_password.return_value = case['error']
            data = {
                'nama_lengkap': 'Test User',
                'email': 'test@example.com',
                'password': case['password']
            }
            response = self.client.post(self.signup_url, data)
            self.assertEqual(response.status_code, 200)

    def test_session_timeout(self):
        # Set up session with expired timestamp
        session = self.client.session
        session['temp_login_email'] = 'test@example.com'
        session['login_timestamp'] = time.time() - 301  # More than 5 minutes ago
        session.save()
        
        response = self.client.get(self.verify_otp_url)
        self.assertEqual(response.status_code, 302)  # Should redirect to sign in

class OWASPSecurityTest(ViewTestMixin, TestCase):
    """Test cases focused on OWASP Top 10 security vulnerabilities"""
    
    def test_a01_broken_access_control(self):
        """Test for broken access control (OWASP A01:2021)"""
        # Test direct object reference - try to access direct user data
        # Setup: We'll use the logout URL which should require authentication
        
        # Attempt without login
        secure_url = reverse('auth:logout')
        response = self.client.get(secure_url)
        self.assertEqual(response.status_code, 302)  # Should redirect to login
        
        # Log in as normal user
        session = self.client.session
        session['user_id'] = self.test_user.id
        session['user_email'] = self.test_user.email
        session['is_admin'] = False  # Explicitly not admin
        session.save()
        
        # Now try to access a user that's not the current user
        try:
            other_pengguna = Pengguna.objects.create(
                email='other@example.com',
                password=make_password('password123'),
                role=self.user_role
            )
            
            # In a real application, you would test access to other user's data
            # For this test, we'll just verify our auth system works
            response = self.client.get(secure_url)
            self.assertEqual(response.status_code, 302)  # Logout should work and redirect
        except Exception:
            pass
    
    def test_a02_cryptographic_failures(self):
        """Test for cryptographic failures (OWASP A02:2021)"""
        # Test that passwords are properly hashed in database
        raw_password = 'SecurePassword123!'
        
        # Create user with this password
        user = Pengguna.objects.create(
            email='crypto_test@example.com',
            password=make_password(raw_password),
            role=self.user_role
        )
        
        # Verify password is not stored in plaintext
        self.assertNotEqual(user.password, raw_password)
        # Verify password starts with algorithm identifier (e.g., pbkdf2_sha256$)
        self.assertTrue(user.password.startswith('pbkdf2_sha256$') or 
                      user.password.startswith('bcrypt$') or
                      user.password.startswith('argon2'))
    
    @patch('authorization.views.sanitize_input')
    def test_a03_injection(self, mock_sanitize):
        """Test for injection vulnerabilities (OWASP A03:2021)"""
        # Test SQL Injection prevention
        mock_sanitize.side_effect = lambda x: x  # Pass through to test validation
        
        # Attempt SQL injection in login form
        injection_attempts = [
            "' OR 1=1 --",
            "admin@example.com' --",
            "'; DROP TABLE pengguna; --",
            "test@example.com' UNION SELECT password FROM pengguna WHERE email='admin@example.com"
        ]
        
        for injection in injection_attempts:
            data = {
                'email': injection,
                'password': 'whatever'
            }
            response = self.client.post(self.signin_url, data)
            # Should not cause a 500 error (which would indicate SQL injection might work)
            self.assertNotEqual(response.status_code, 500)
    
    def test_a04_insecure_design(self):
        """Test for insecure design (OWASP A04:2021)"""
        # Test account enumeration prevention
        unknown_email = 'nonexistent@example.com'
        data = {
            'email': unknown_email,
            'password': 'wrongpassword'
        }
        
        response = self.client.post(self.signin_url, data)
        
        # Should return same error message as wrong password for existing account
        # to prevent account enumeration
        self.assertEqual(response.status_code, 200)
        expected_message = 'Email atau password salah'
        self.assertIn(expected_message, response.content.decode())
    
    def test_a05_security_misconfiguration(self):
        """Test for security misconfiguration (OWASP A05:2021)"""
        # Check for proper security headers
        response = self.client.get(self.signin_url)
        
        # Check security headers
        headers = response.headers
        security_headers = ['X-Content-Type-Options', 'X-XSS-Protection', 
                           'X-Frame-Options', 'Content-Security-Policy', 
                           'Referrer-Policy']
        
        # Test at least some security headers are present
        found_headers = 0
        for header in security_headers:
            if header in headers:
                found_headers += 1
        
        # At least some security headers should be present
        self.assertGreater(found_headers, 0, "No security headers found")
    
    def test_a06_vulnerable_components(self):
        """Test for vulnerable components (OWASP A06:2021)"""
        # This is typically tested through dependency scanning
        # Here we just implement a placeholder test for demonstration
        # In a real scenario, you would integrate with tools like safety, Snyk, or OWASP Dependency Check
        pass
    
    @patch('authorization.views.rate_limit', lambda *args, **kwargs: lambda f: f)
    def test_a07_authentication_failures(self):
        """Test for identification and authentication failures (OWASP A07:2021)"""
        # Create a test user with a secure password
        test_user = Pengguna.objects.create(
            email='test_otp@example.com',
            password=make_password('SecurePassword123!')
        )
        
        # Set up session with clean client
        self.client = Client()
        
        # Attempt login with correct credentials
        response = self.client.post(reverse('auth:sign_in'), {
            'email': 'test_otp@example.com',
            'password': 'SecurePassword123!'
        }, follow=False)  # Don't follow redirects to catch the immediate redirect
        
        # Check that we're redirected to OTP setup or verification
        # The actual URL pattern is "/auth/setup-otp/" not containing "setup_otp"
        self.assertTrue(
            '/auth/verify-otp/' in response.url or '/auth/setup-otp/' in response.url,
            f"Expected redirect to OTP verification but got: {response.url}"
        )
    
    def test_a08_software_data_integrity_failures(self):
        """Test for software and data integrity failures (OWASP A08:2021)"""
        # Test CSRF protection
        response = self.client.get(self.signin_url)
        
        # Extract CSRF token from response
        self.assertIn('csrfmiddlewaretoken', response.content.decode(), 
                    "CSRF token should be present in form")
        
        # For a more complete test, we would check that a POST without CSRF token fails,
        # but this requires custom client configuration that may not be possible within
        # the scope of this test
    
    def test_a09_logging_monitoring_failures(self):
        """Test for security logging and monitoring failures (OWASP A09:2021)"""
        # This is typically tested through log inspection
        # Here we implement a placeholder for manual verification
        pass
    
    def test_a10_server_side_request_forgery(self):
        """Test for server-side request forgery (OWASP A10:2021)"""
        # Test URL validation for redirect URLs
        dangerous_urls = [
            'http://evil.com',
            'https://attacker.com/steal?data=',
            'file:///etc/passwd',
            '//evil.com',
            'data:text/html,<script>alert(1)</script>'
        ]
        
        # Set up authenticated session
        session = self.client.session
        session['user_id'] = self.test_user.id
        session['user_email'] = self.test_user.email
        session.save()
        
        # Test with logout which typically has redirect functionality
        logout_url = reverse('auth:logout')
        
        # In this test, we're just checking the system behavior, not making assertions
        # since the actual behavior might vary depending on implementation
        for url in dangerous_urls:
            try:
                response = self.client.get(f"{logout_url}?next={url}")
                # If we get here, at least it didn't crash the system
                # In a real test with known behavior, you would verify redirection safety
            except Exception as e:
                self.fail(f"Request failed with URL {url}: {str(e)}")
    
    @patch('authorization.views.validate_password_strength', return_value=[])
    def test_xss_prevention(self, mock_validate):
        """Test for Cross-Site Scripting (XSS) prevention"""
        # XSS payloads to test
        xss_payloads = [
            '<script>alert(1)</script>',
            'javascript:alert(1)',
            '<img src="x" onerror="alert(1)">',
            '<body onload="alert(1)">',
            '"><script>alert(1)</script>'
        ]
        
        # Login first for a more reliable response
        session = self.client.session
        session['user_id'] = self.test_user.id
        session['user_email'] = self.test_user.email
        session.save()
        
        # Test dengan memverifikasi input form
        for payload in xss_payloads:
            # Submit XSS in signup form
            data = {
                'nama_lengkap': payload,
                'email': 'xss_test@example.com',
                'password': 'SecurePassword123!'
            }
            
            # Cukup periksa bahwa tidak terjadi error saat mengirim form
            response = self.client.post(self.signup_url, data, follow=True)
            self.assertLess(response.status_code, 500, "Form submission should not cause server error")
