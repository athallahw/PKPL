from django.db import models
from authorization.models import Pengguna

class DailyQuestionnaire(models.Model):
    user = models.ForeignKey(Pengguna, on_delete=models.CASCADE)
    date = models.DateField(auto_now_add=True)
    
    # Basic Information
    weight = models.FloatField(help_text="Berat badan dalam kg")
    height = models.FloatField(help_text="Tinggi badan dalam cm")
    gender = models.CharField(max_length=10, choices=[('pria', 'Pria'), ('wanita', 'Wanita')])
    age = models.IntegerField(help_text="Usia dalam tahun")
    
    # Lifestyle Information
    water_intake = models.IntegerField(help_text="Asupan air dalam ml")
    sport_frequency = models.FloatField(help_text="Frekuensi olahraga (1.2-1.9)")
    smoke_frequency = models.IntegerField(help_text="Jumlah rokok per hari")
    stress_level = models.IntegerField(help_text="Tingkat stres (1-10)")
    alcohol_frequency = models.IntegerField(help_text="Jumlah minum alkohol per minggu")
    daily_calories = models.IntegerField(help_text="Asupan kalori harian")
    sleep_amount = models.FloatField(help_text="Jumlah tidur dalam jam")

    class Meta:
        ordering = ['-date']
        verbose_name = 'Kuesioner Harian'
        verbose_name_plural = 'Kuesioner Harian'

    def __str__(self):
        return f"Kuesioner {self.user.email} - {self.date}"
