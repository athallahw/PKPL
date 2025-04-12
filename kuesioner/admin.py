from django.contrib import admin
from .models import DailyQuestionnaire

@admin.register(DailyQuestionnaire)
class DailyQuestionnaireAdmin(admin.ModelAdmin):
    list_display = ('user', 'date', 'weight', 'height', 'gender', 'age')
    list_filter = ('date', 'gender')
    search_fields = ('user__username',)
    ordering = ('-date',)
