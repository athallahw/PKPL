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

    if request.method == 'POST':
        try:
            # Check if user has already submitted today's questionnaire
            today = timezone.now().date()
            if DailyQuestionnaire.objects.filter(user=user, date=today).exists():
                messages.warning(request, 'Anda sudah mengisi kuesioner hari ini.')
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
            messages.success(request, 'Kuesioner berhasil disimpan!')
            return redirect('kuesioner:questionnaire_form')
        except Exception as e:
            messages.error(request, f'Terjadi kesalahan: {str(e)}')
            return redirect('kuesioner:questionnaire_form')
    
    return render(request, 'kuesioner/form.html')

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
