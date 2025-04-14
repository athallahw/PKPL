from django.core.management.base import BaseCommand
from django.core.mail import send_mail
from django.conf import settings

class Command(BaseCommand):
    help = 'Test email configuration'

    def handle(self, *args, **options):
        try:
            send_mail(
                'Test Email dari PKPL',
                'Ini adalah email test untuk memverifikasi konfigurasi email.',
                None,  # Will use EMAIL_HOST_USER from settings
                [settings.EMAIL_HOST_USER],  # Send to self for testing
                fail_silently=False,
            )
            self.stdout.write(self.style.SUCCESS('Email test berhasil dikirim!'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Gagal mengirim email: {str(e)}')) 