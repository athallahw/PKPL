import pytest
from django.urls import reverse
from django.contrib.auth.hashers import make_password
from django.test import Client
from datetime import datetime
from authorization.models import Pengguna, Role
from kuesioner.models import DailyQuestionnaire

# Fixture untuk bypass login_required sehingga decorator tidak melakukan pengecekan
@pytest.fixture(autouse=True)
def bypass_login_required(monkeypatch):
    # Patch decorator login_required sehingga hanya mengembalikan fungsi aslinya
    monkeypatch.setattr("django.contrib.auth.decorators.login_required", lambda f: f)

@pytest.mark.django_db
class TestShowStatus:

    @pytest.fixture
    def client_logged_in(self):
        # Setup Role dan Pengguna
        role_user = Role.objects.create(role_name="User")
        password = "UserPass123!"
        pengguna = Pengguna.objects.create(
            email="user@example.com",
            password=make_password(password),
            role=role_user
        )
        client = Client()
        # Atur session secara manual untuk mensimulasikan login
        session = client.session
        session['user_id'] = pengguna.id
        session['user_email'] = pengguna.email
        session['session_rotated'] = False
        session.save()
        return client, pengguna

    def test_show_status_no_data(self, client_logged_in):
        client, pengguna = client_logged_in
        response = client.get(reverse('health_status:show_status'))
        assert response.status_code == 200
        assert b"Belum ada data yang diisi." in response.content

    def test_show_status_with_data(self, client_logged_in):
        client, pengguna = client_logged_in
        DailyQuestionnaire.objects.create(
            user=pengguna,
            date=datetime.today().date(),
            weight=70,
            height=170,
            gender="Pria",
            age=25,
            water_intake=2000,
            sport_frequency=1.5,
            smoke_frequency=0,
            stress_level=3,
            alcohol_frequency=0,
            daily_calories=2500,
            sleep_amount=8
        )
        response = client.get(reverse('health_status:show_status'))
        assert response.status_code == 200
        assert b"Status Kesehatan Anda" in response.content
        assert b"BMI" in response.content
        assert b"Risiko Penyakit" in response.content

    def test_show_status_invalid_date_injection_attempt(self, client_logged_in):
        client, pengguna = client_logged_in
        malicious_date = "2024-01-01' OR '1'='1"
        response = client.get(reverse('health_status:show_status') + f"?date={malicious_date}")
        # Karena ada validasi regex, seharusnya terjadi redirect
        assert response.status_code == 302
        assert response.url == reverse('main:landing_page')
# import pytest
# from django.urls import reverse
# from django.contrib.auth.models import AnonymousUser
# from authorization.models import Pengguna, Normal
# from kuesioner.models import DailyQuestionnaire
# from datetime import date
# from django.contrib.auth.hashers import make_password
# from authorization.models import Pengguna, Normal, Role, Admin

# # ------------------------- Fixtures -------------------------
# @pytest.fixture
# def user(db):
#     role_user = Role.objects.create(role_name="User")
#     user = Pengguna.objects.create(
#         email="user@example.com",
#         password=make_password("UserPass123!"),
#         role=role_user
#     )
#     return user

# @pytest.fixture
# def daily_data(db, user):
#     return DailyQuestionnaire.objects.create(
#         user=user,
#         weight=70,
#         height=175,
#         gender="pria",
#         age=25,
#         water_intake=2000,
#         sport_frequency=1.55,
#         smoke_frequency=0,
#         stress_level=3,
#         alcohol_frequency=1,
#         daily_calories=2500,
#         sleep_amount=7
#     )

# # ------------------------- Functional Tests -------------------------
# def test_show_status_redirect_if_not_authenticated(client):
#     response = client.get(reverse('health_report'))
#     assert response.status_code == 302  # Redirect ke login

# def test_show_status_with_authenticated_user(client, user, daily_data):
#     client.force_login(user)
#     response = client.get(reverse('health_report'))
    
#     assert response.status_code == 200
#     assert 'BMI' in response.context
#     assert 'BMR' in response.context

# def test_filter_by_date(client, user, daily_data):
#     client.force_login(user)
#     current_date = date.today().strftime("%Y-%m-%d")
#     response = client.get(f"{reverse('health_report')}?date={current_date}")
    
#     assert response.status_code == 200
#     assert str(daily_data.weight) in str(response.content)

# def test_invalid_date_format(client, user):
#     client.force_login(user)
#     response = client.get(reverse('health_report') + '?date=invalid-date')
    
#     assert response.status_code == 302  # Redirect karena format invalid
#     assert response.url == reverse('main:landing_page')

# def test_no_data(client, user):
#     client.force_login(user)
#     DailyQuestionnaire.objects.all().delete()
#     response = client.get(reverse('health_report'))
    
#     assert "Belum ada data" in str(response.content)
#     assert response.status_code == 200

# # ------------------------- OWASP Test (SQL Injection) -------------------------
# def test_sql_injection_via_date_param(client, user):
#     client.force_login(user)
#     malicious_date = "2023-10-01' OR 1=1 --"
#     response = client.get(f"{reverse('health_report')}?date={malicious_date}")
    
#     assert response.status_code == 302  # Harusnya redirect karena format salah
#     assert DailyQuestionnaire.objects.count() == 0  # Pastikan tidak ada data yang diinject

