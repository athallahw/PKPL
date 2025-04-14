from django.shortcuts import render, redirect
from django.contrib import messages
from .models import DailyQuestionnaire
from django.utils import timezone
from authorization.models import Pengguna

# Create your views here.

def questionnaire_form(request):
    # Check if user is logged in via session
    if 'user_id' not in request.session:
        return redirect('auth:sign_in')
    
    user_id = request.session.get('user_id')
    try:
        user = Pengguna.objects.get(id=user_id)
    except Pengguna.DoesNotExist:
        return redirect('auth:sign_in')

    # Check if user has already submitted today's questionnaire
    today = timezone.now().date()
    already_submitted = DailyQuestionnaire.objects.filter(user=user, date=today).exists()
    
    if already_submitted:
        messages.warning(request, 'Anda sudah mengisi kuesioner hari ini.')
        return render(request, 'kuesioner/form.html', {'already_submitted': True})
    
    if request.method == 'POST':
        try:
            # Validate required fields
            required_fields = [
                'weight', 'height', 'gender', 'age', 'water_intake',
                'sport_frequency', 'smoke_frequency', 'stress_level',
                'alcohol_frequency', 'daily_calories', 'sleep_amount'
            ]
            
            # Check if all required fields are present
            for field in required_fields:
                if not request.POST.get(field):
                    messages.error(request, f'Mohon isi semua field yang diperlukan.')
                    return redirect('kuesioner:questionnaire_form')
            
            # Validate field ranges
            validations = {
                'weight': (30, 300),
                'height': (100, 250),
                'age': (1, 120),
                'water_intake': (0, 10000),
                'sport_frequency': (1.2, 1.9),
                'smoke_frequency': (0, 100),
                'alcohol_frequency': (0, 100),
                'daily_calories': (500, 10000),
                'sleep_amount': (0, 24)
            }
            
            for field, (min_val, max_val) in validations.items():
                try:
                    value = float(request.POST.get(field))
                    if value < min_val or value > max_val:
                        messages.error(request, f'Nilai {field} harus antara {min_val} dan {max_val}.')
                        return redirect('kuesioner:questionnaire_form')
                except (ValueError, TypeError):
                    messages.error(request, f'Nilai tidak valid untuk field {field}.')
                    return redirect('kuesioner:questionnaire_form')
            
            # Create new questionnaire entry
            DailyQuestionnaire.objects.create(
                user=user,
                weight=float(request.POST.get('weight')),
                height=float(request.POST.get('height')),
                gender=request.POST.get('gender'),
                age=int(request.POST.get('age')),
                water_intake=int(request.POST.get('water_intake')),
                sport_frequency=float(request.POST.get('sport_frequency')),
                smoke_frequency=int(request.POST.get('smoke_frequency')),
                stress_level=int(request.POST.get('stress_level')),
                alcohol_frequency=int(request.POST.get('alcohol_frequency')),
                daily_calories=int(request.POST.get('daily_calories')),
                sleep_amount=float(request.POST.get('sleep_amount'))
            )
            
            # Store success message in session
            messages.success(request, 'Kuesioner berhasil ditambahkan!')
            return redirect('kuesioner:questionnaire_history')
        except Exception as e:
            messages.error(request, f'Terjadi kesalahan: {str(e)}')
            return redirect('kuesioner:questionnaire_form')
    
    return render(request, 'kuesioner/form.html', {'already_submitted': False})

def questionnaire_history(request):
    # Check if user is logged in via session
    if 'user_id' not in request.session:
        return redirect('auth:sign_in')
    
    user_id = request.session.get('user_id')
    try:
        user = Pengguna.objects.get(id=user_id)
        questionnaires = DailyQuestionnaire.objects.filter(user=user).order_by('-date')
        return render(request, 'kuesioner/history.html', {'questionnaires': questionnaires})
    except Pengguna.DoesNotExist:
        return redirect('auth:sign_in')
