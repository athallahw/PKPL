
from datetime import datetime
from django.shortcuts import render, redirect
from django.db import connection
import uuid
from django.contrib import messages
from authorization.models import Pengguna
from kuesioner.models import DailyQuestionnaire
import re
import logging
from django.contrib.auth.decorators import login_required


# Konfigurasi logger untuk mencatat pesan ke terminal
logger = logging.getLogger('django')
handler = logging.StreamHandler()  # Menampilkan log ke terminal
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Create your views here.


@login_required
def show_status(Request) :
    
    if 'user_id' not in Request.session:
        return redirect('auth:sign_in')
    
    user_id = Request.session.get('user_id')
    try:
        user = Pengguna.objects.get(id=user_id)
    except Pengguna.DoesNotExist:
        return redirect('auth:sign_in')
    
    logger.info("Pengguna mengakses status kesehatan")

    all_dates = DailyQuestionnaire.objects.filter(user=user).order_by('-date').values_list('date', flat=True)
    
   

    selected_date = Request.GET.get('date')

# ganti sesuai view-mu
    if selected_date:
        if selected_date and not re.match(r'^\d{4}-\d{2}-\d{2}$', selected_date):
            # Log pesan error ke terminal
            logger.error(f"Format tanggal tidak valid. Tanggal yang diberikan: {selected_date}")
            return redirect('main:landing_page')
        data = DailyQuestionnaire.objects.filter(user=user, date=selected_date)
    else:
        data = DailyQuestionnaire.objects.filter(user=user).first()
    
    if not data:
        messages.error(Request, "Belum ada data yang diisi.")
        logger.error("Belum ada data yang diisi")
        return render(Request, "health_report.html")  # Atau redirect ke form

   
    context = generate_status(
        Weight=data.weight,
        Height=data.height, 
        Gender=data.gender,
        Age=data.age,
        WaterIntake=data.water_intake,
        SportFreq=data.sport_frequency,
        SmokeFreq=data.smoke_frequency,
        Stress=data.stress_level,
        AlcoholFreq=data.alcohol_frequency,
        DailyCalories=data.daily_calories,
        SleepAmount=data.sleep_amount,
        Date=data.date
    )
    context["available_dates"] = all_dates
    context["selected_date"] = data.date

    return render(Request, "health_report.html", context)

def generate_status(Weight, Height, Gender, Age, WaterIntake, SportFreq, SmokeFreq, Stress, AlcoholFreq, DailyCalories, SleepAmount, Date) :
    BMI = Weight / (Height/100 * Height/100)
    BMR = 0
    
    if Gender == "Pria" :
        BMR += (Weight * 10) + (Height * 6.25) - (5 * Age) + 5
        
    else :
        BMR += (Weight * 10) + (Height * 6.25) - (5 * Age) - 161
        
    TDEE = BMR * SportFreq
    
    
    water_needs = Weight * 30
    if SportFreq > 1.375 :
        water_needs += 500
    
    return {
        "BMI" : BMI,
        "BMR" : BMR,
        "TDEE" : TDEE,
        "resiko_penyakit_jantung" : resiko_jantung(BMI, SportFreq, SmokeFreq, Stress, AlcoholFreq),
        "resiko_penyakit_paru" : kategori_kesehatan_paru(SmokeFreq, SportFreq),
        "resiko_penyakit_hati" : kategori_kesehatan_hati(AlcoholFreq, BMI, DailyCalories, TDEE),
        "Kebugaran_badan" : kategori_kebugaran(BMI, SportFreq, TDEE, SleepAmount, Stress, DailyCalories),
        "status_hidrasi" : kategori_hidrasi(WaterIntake, water_needs),
        
    }
    
def hitung_poin(nilai, kategori):
    for batas_bawah, batas_atas, skor in kategori:
        if batas_bawah <= nilai <= batas_atas:
            return skor
    return kategori[-1][2] 

def resiko_jantung(BMI, SportFreq, SmokeFreq, Stress, AlcoholFreq):
    point = 0

    # Kategori skor berdasarkan rentang nilai
    bmi_kategori = [(0, 24.9, 1), (25, 29.9, 2), (30, float('inf'), 3)]
    sport_kategori = [(150, float('inf'), 1), (75, 149, 2), (0, 74, 3)]
    smoke_kategori = [(0, 0, 1), (1, 3, 2), (4, float('inf'), 3)]
    stress_kategori = [(1, 3, 1), (4, 6, 2), (7, 10, 3)]
    alcohol_kategori = [(0, 1, 1), (2, 3, 2), (4, float('inf'), 3)]

    # Menentukan poin berdasarkan kategori
    point += hitung_poin(BMI, bmi_kategori)
    point += hitung_poin(SportFreq, sport_kategori)
    point += hitung_poin(SmokeFreq, smoke_kategori)
    point += hitung_poin(Stress, stress_kategori)
    point += hitung_poin(AlcoholFreq, alcohol_kategori)

    # Menentukan kategori risiko
    if point <= 5:
        return "Risiko Rendah"
    elif 6 <= point <= 10:
        return "Risiko Sedang"
    else:
        return "Risiko Tinggi"

def kategori_kebugaran(BMI,SportFreq, TDEE, Tidur, Stres, DailyCalories):
    point = 0

    Kalori = abs(TDEE - DailyCalories)
    # Kategori skor berdasarkan rentang nilai
    bmi_kategori = [(18.5, 24.9, 1), (25, 29.9, 2), (30, 34.9, 3), (35, float('inf'), 4)]
    whtr_kategori = [(0, 0.49, 1), (0.5, 0.52, 2), (0.53, 0.55, 3), (0.56, 0.6, 4), (0.61, float('inf'), 5)]
    sport_kategori = [(300, float('inf'), 1), (150, 299, 2), (75, 149, 3), (1, 74, 4), (0, 0, 5)]
    kalori_kategori = [(0, 200, 1), (201, 300, 2), (301, 500, 3), (501, 800, 4), (801, float('inf'), 5)]
    tidur_kategori = [(7, 9, 1), (6, 8, 2), (5.5, 7, 3), (5, 5.5, 4), (float('-inf'), 5, 5)]
    stres_kategori = [(1, 3, 1), (4, 6, 2), (4, 6, 3), (7, 10, 4), (8, 10, 5)]

    # Menentukan poin berdasarkan kategori
    point += hitung_poin(BMI, bmi_kategori)
    point += hitung_poin(SportFreq, sport_kategori)
    point += hitung_poin(Kalori, kalori_kategori)
    point += hitung_poin(Tidur, tidur_kategori)
    point += hitung_poin(Stres, stres_kategori)

    # Menentukan kategori kebugaran fisik
    if point <= 6:
        return "Sangat Bugar"
    elif 7 <= point <= 10:
        return "Bugar"
    elif 11 <= point <= 14:
        return "Standar (Cukup Bugar)"
    elif 15 <= point <= 18:
        return "Kurang Bugar"
    else:
        return "Sangat Tidak Bugar"
    


def kategori_hidrasi(air_diminum, kebutuhan_air):
    
    if kebutuhan_air <= 0:
        return "Kebutuhan air tidak valid"

    tingkat_hidrasi = (air_diminum / kebutuhan_air) * 100

    if tingkat_hidrasi > 120:
        return "Sangat Terhidrasi"
    elif 100 <= tingkat_hidrasi <= 120:
        return "Cukup Terhidrasi"
    elif 80 <= tingkat_hidrasi < 100:
        return "Standar (Cukup, tapi bisa lebih baik) "
    elif 50 <= tingkat_hidrasi < 80:
        return "Kurang Terhidrasi"
    else:
        return "Potensi Dehidrasi"
    
def hitung_poin(nilai, kategori_list):
    for batas_bawah, batas_atas, poin in kategori_list:
        if batas_bawah <= nilai <= batas_atas:
            return poin
    return 0  

def kategori_kesehatan_paru(smoke_freq, exercise_minutes):
    point = 0

    # Kategori skor berdasarkan rentang nilai
    smoke_kategori = [(0, 1, 1), (2, 10, 2), (11, float('inf'), 3)]
    sport_kategori = [(1.55, float('inf'), 1), (1.375, 1.375, 2), (0, 1.2, 3)]

    # Menentukan poin berdasarkan kategori
    point += hitung_poin(smoke_freq, smoke_kategori)
    point += hitung_poin(exercise_minutes, sport_kategori)

    # Menentukan kategori kesehatan paru-paru
    if point <= 2:
        return "Risiko Rendah"
    elif 3 <= point <= 4:
        return "Risiko Sedang"
    else:
        return "Risiko Tinggi"
    
def kategori_kesehatan_hati(alcohol_freq, BMI, daily_calories, TDEE):
    
    point = 0

    # Menghitung surplus/defisit kalori harian
    kalori = abs(daily_calories - TDEE)

    # Kategori skor berdasarkan rentang nilai
    alcohol_kategori = [(0, 1, 1), (2, 3, 2), (4, float('inf'), 3)]
    bmi_kategori = [(18.5, 24.9, 1), (25, 29.9, 2), (30, float('inf'), 3)]
    kalori_kategori = [(0, 200, 1), (201, 500, 2), (501, float('inf'), 3)]

    # Menentukan poin berdasarkan kategori
    point += hitung_poin(alcohol_freq, alcohol_kategori)
    point += hitung_poin(BMI, bmi_kategori)
    point += hitung_poin(kalori, kalori_kategori)

    # Menentukan kategori kesehatan hati
    if point <= 3:
        return "Risiko Rendah"
    elif 4 <= point <= 6:
        return "Risiko Sedang"
    else:
        return "Risiko Tinggi"

