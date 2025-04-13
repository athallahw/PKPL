from django.core.management.base import BaseCommand
from django.core.mail import send_mail
from django.utils import timezone
from authorization.models import Pengguna
from kuesioner.models import DailyQuestionnaire
from datetime import datetime, timedelta

class Command(BaseCommand):
    help = 'Sends questionnaire reminders to users who haven\'t filled out today\'s questionnaire'

    def handle(self, *args, **options):
        # Get current date in local timezone
        today = timezone.now().date()
        
        # Get all users
        users = Pengguna.objects.all()
        
        for user in users:
            # Check if user has already filled out today's questionnaire
            has_filled = DailyQuestionnaire.objects.filter(
                user=user,
                date=today
            ).exists()
            
            if not has_filled:
                try:
                    # Send email reminder
                    send_mail(
                        'Pengingat Kuesioner Harian PKPL',
                        'Selamat malam, jangan lupa mengisi kuesioner harian kesehatan hari ini',
                        None,  # Will use EMAIL_HOST_USER from settings
                        [user.email],
                        fail_silently=False,
                    )
                    self.stdout.write(self.style.SUCCESS(f'Successfully sent reminder to {user.email}'))
                except Exception as e:
                    self.stdout.write(self.style.ERROR(f'Failed to send reminder to {user.email}: {str(e)}')) 