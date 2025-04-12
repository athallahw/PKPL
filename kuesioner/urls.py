from django.urls import path
from . import views

app_name = 'kuesioner'

urlpatterns = [
    path('', views.questionnaire_form, name='questionnaire_form'),
    path('history/', views.questionnaire_history, name='questionnaire_history'),
] 