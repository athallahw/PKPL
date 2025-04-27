from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.messages import get_messages
from authorization.models import Pengguna, Normal, Role
from django.contrib.auth.hashers import make_password
from django.http import HttpRequest
from unittest.mock import patch, MagicMock
from django.utils import timezone
import datetime

class ViewTestMixin:
    """Mixin with common test methods to avoid duplication"""
    
    def setUp(self):
        self.client = Client()
        self.user_role = Role.objects.create(role_name='pengguna')
        
        # Create test user with hashed password
        self.password = 'TestPassword123!'
        self.test_user = Pengguna.objects.create(
            email='test@example.com',
            password=make_password(self.password),
            role=self.user_role
        )
        self.normal_user = Normal.objects.create(
            pengguna=self.test_user,
            nama_depan='Test',
            nama_belakang='User',
            nama='Test User',
            poin=0
        )
        
        # Set up session for all tests
        session = self.client.session
        session['user_id'] = self.test_user.id
        session['user_email'] = self.test_user.email
        session['session_rotated'] = False
        session.save()
        
        # Get CSRF token for all tests
        response = self.client.get(reverse('kuesioner:questionnaire_form'))
        self.csrf_token = response.cookies['csrftoken'].value

class KuesionerOWASPTestCase(ViewTestMixin, TestCase):
    """Test cases focused on OWASP Top 10 security vulnerabilities for kuesioner app"""
    
    def test_a01_broken_access_control(self):
        """Test for broken access control (OWASP A01:2021)"""
        # Create a new client without session
        client = Client()
        
        # Attempt without login
        secure_url = reverse('kuesioner:questionnaire_form')
        response = client.get(secure_url)
        self.assertEqual(response.status_code, 302)  # Should redirect to login
        
        # Now try with authenticated session
        response = self.client.get(secure_url)
        self.assertEqual(response.status_code, 200)  # Should be accessible after login
    
    def test_a02_cryptographic_failures(self):
        """Test for cryptographic failures (OWASP A02:2021)"""
        # Test that sensitive data is properly handled
        raw_password = 'SecurePassword123!'
        
        # Create user with this password
        user = Pengguna.objects.create(
            email='crypto_test@example.com',
            password=make_password(raw_password),
            role=self.user_role
        )
        
        # Verify password is not stored in plaintext
        self.assertNotEqual(user.password, raw_password)
        # Verify password starts with algorithm identifier
        self.assertTrue(user.password.startswith('pbkdf2_sha256$') or 
                      user.password.startswith('bcrypt$') or
                      user.password.startswith('argon2'))
    
    def test_a03_injection(self):
        """Test for injection vulnerabilities (OWASP A03:2021)"""
        # Attempt SQL injection in kuesioner form
        injection_attempts = [
            "' OR 1=1 --",
            "'; DROP TABLE kuesioner; --",
            "1' UNION SELECT * FROM kuesioner; --"
        ]
        
        for injection in injection_attempts:
            data = {
                'csrfmiddlewaretoken': self.csrf_token,
                'weight': injection,
                'height': injection,
                'gender': 'pria',
                'age': '25',
                'water_intake': '2000',
                'sport_frequency': '1.5',
                'smoke_frequency': '0',
                'stress_level': '5',
                'alcohol_frequency': '0',
                'daily_calories': '2000',
                'sleep_amount': '8'
            }
            response = self.client.post(reverse('kuesioner:questionnaire_form'), data)
            # Should not cause a 500 error
            self.assertNotEqual(response.status_code, 500)
    
    def test_a04_insecure_design(self):
        """Test for insecure design (OWASP A04:2021)"""
        # Test with invalid input
        invalid_data = {
            'csrfmiddlewaretoken': self.csrf_token,
            'weight': '0',  # Invalid weight
            'height': '0',  # Invalid height
            'gender': '',  # Empty gender
            'age': '0',  # Invalid age
            'water_intake': '-1',  # Invalid water intake
            'sport_frequency': '0',  # Invalid sport frequency
            'smoke_frequency': '-1',  # Invalid smoke frequency
            'stress_level': '0',  # Invalid stress level
            'alcohol_frequency': '-1',  # Invalid alcohol frequency
            'daily_calories': '0',  # Invalid calories
            'sleep_amount': '-1'  # Invalid sleep amount
        }
        
        response = self.client.post(reverse('kuesioner:questionnaire_form'), invalid_data, follow=True)
        self.assertEqual(response.status_code, 200)  # Should return to form
        self.assertIn('is-invalid', response.content.decode().lower())
    
    def test_a05_security_misconfiguration(self):
        """Test for security misconfiguration (OWASP A05:2021)"""
        # Check for proper security headers
        response = self.client.get(reverse('kuesioner:questionnaire_form'))
        
        # Check security headers
        headers = response.headers
        security_headers = ['X-Content-Type-Options', 'X-XSS-Protection', 
                           'X-Frame-Options', 'Content-Security-Policy']
        
        # Test at least some security headers are present
        found_headers = 0
        for header in security_headers:
            if header in headers:
                found_headers += 1
        
        self.assertGreater(found_headers, 0, "No security headers found")
    
    def test_a08_software_data_integrity(self):
        """Test for software and data integrity failures (OWASP A08:2021)"""
        # Test CSRF protection
        response = self.client.get(reverse('kuesioner:questionnaire_form'))
        
        # Extract CSRF token from response
        self.assertIn('csrfmiddlewaretoken', response.content.decode(), 
                    "CSRF token should be present in form")
    
    def test_a09_logging_monitoring(self):
        """Test for security logging and monitoring failures (OWASP A09:2021)"""
        # Test suspicious activity detection
        request = HttpRequest()
        request.session = {'user_id': self.test_user.id}
        request.META = {'REMOTE_ADDR': '127.0.0.1'}
        
        # Mock the current hour to be suspicious time
        with patch('django.utils.timezone.now') as mock_now:
            mock_now.return_value = timezone.make_aware(
                datetime.datetime(2024, 1, 1, 3, 0, 0)
            )
            
            # Simulate suspicious activity with multiple requests
            for _ in range(100):
                response = self.client.post(
                    reverse('kuesioner:questionnaire_form'),
                    {
                        'csrfmiddlewaretoken': self.csrf_token,
                        'weight': '70',
                        'height': '170',
                        'gender': 'pria',
                        'age': '25',
                        'water_intake': '2000',
                        'sport_frequency': '1.5',
                        'smoke_frequency': '0',
                        'stress_level': '5',
                        'alcohol_frequency': '0',
                        'daily_calories': '2000',
                        'sleep_amount': '8'
                    }
                )
            
            # Verify response is not a 500 error
            self.assertNotEqual(response.status_code, 500)

class XSSVulnerabilityTest(TestCase):
    def setUp(self):
        self.user_role = Role.objects.create(role_name="User")
        self.user = Pengguna.objects.create(
            email="user@example.com",
            password=make_password("StrongPass123!"),
            role=self.user_role
        )
        self.normal_user = Normal.objects.create(
            pengguna=self.user,
            nama_depan="<script>alert('XSS')</script>",
            nama_belakang="User",
            nama="<script>alert('XSS')</script> User",
            poin=1000
        )
        
        self.client = Client()
        session = self.client.session
        session['user_id'] = self.user.id
        session['user_email'] = self.user.email
        session['session_rotated'] = False
        session.save()
        
        # Get CSRF token
        response = self.client.get(reverse('kuesioner:questionnaire_form'))
        self.csrf_token = response.cookies['csrftoken'].value
        
    def test_xss_in_kuesioner_display(self):
        """Test that XSS is not possible through user input in kuesioner pages"""
        # Test XSS in form submission
        data = {
            'csrfmiddlewaretoken': self.csrf_token,
            'weight': '70',
            'height': '170',
            'gender': 'pria',
            'age': '25',
            'water_intake': '2000',
            'sport_frequency': '1.5',
            'smoke_frequency': '0',
            'stress_level': '5',
            'alcohol_frequency': '0',
            'daily_calories': '2000',
            'sleep_amount': '8'
        }
        response = self.client.post(reverse('kuesioner:questionnaire_form'), data)
        self.assertNotIn("<script>alert('XSS')</script>", response.content.decode())

class CSRFVulnerabilityTest(TestCase):
    def setUp(self):
        self.user_role = Role.objects.create(role_name="User")
        self.user = Pengguna.objects.create(
            email="user@example.com",
            password=make_password("StrongPass123!"),
            role=self.user_role
        )
        self.normal_user = Normal.objects.create(
            pengguna=self.user,
            nama="Test User",
            poin=1000
        )
        
        self.client = Client(enforce_csrf_checks=True)
        session = self.client.session
        session['user_id'] = self.user.id
        session['user_email'] = self.user.email
        session['session_rotated'] = False
        session.save()
        
        # Get CSRF token
        response = self.client.get(reverse('kuesioner:questionnaire_form'))
        self.csrf_token = response.cookies['csrftoken'].value
    
    def test_csrf_protection(self):
        """Test that CSRF protection works for kuesioner POST requests"""
        # Without CSRF token, should fail
        response = self.client.post(reverse('kuesioner:questionnaire_form'), {
            'weight': '70',
            'height': '170',
            'gender': 'pria',
            'age': '25',
            'water_intake': '2000',
            'sport_frequency': '1.5',
            'smoke_frequency': '0',
            'stress_level': '5',
            'alcohol_frequency': '0',
            'daily_calories': '2000',
            'sleep_amount': '8'
        })
        self.assertEqual(response.status_code, 403)  # CSRF failure returns 403 Forbidden
        
        # With CSRF token, should succeed
        response = self.client.post(
            reverse('kuesioner:questionnaire_form'),
            {
                'csrfmiddlewaretoken': self.csrf_token,
                'weight': '70',
                'height': '170',
                'gender': 'pria',
                'age': '25',
                'water_intake': '2000',
                'sport_frequency': '1.5',
                'smoke_frequency': '0',
                'stress_level': '5',
                'alcohol_frequency': '0',
                'daily_calories': '2000',
                'sleep_amount': '8'
            }
        )
        self.assertNotEqual(response.status_code, 403)
