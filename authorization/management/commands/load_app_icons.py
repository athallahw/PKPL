import os
from django.core.management.base import BaseCommand
from django.core.files import File
from authorization.models import AppIcon

class Command(BaseCommand):
    help = 'Load initial app icons'

    def handle(self, *args, **kwargs):
        self.stdout.write('Loading app icons...')
        
        # Define icons to load
        icons_data = [
            {
                'name': 'Google Authenticator',
                'description': 'Google\'s two-factor authentication app',
                'filename': 'google_auth.png',
            },
            {
                'name': 'Authy',
                'description': 'Twilio\'s two-factor authentication app',
                'filename': 'authy.png',
            },
            {
                'name': 'Microsoft Authenticator',
                'description': 'Microsoft\'s two-factor authentication app',
                'filename': 'microsoft_auth.png',
            },
        ]
        
        # Base directory where icon images are stored
        icons_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 
                               '../../../static/img')
        
        for icon_data in icons_data:
            # Check if icon already exists
            if not AppIcon.objects.filter(name=icon_data['name']).exists():
                try:
                    # Create the app icon
                    icon = AppIcon(
                        name=icon_data['name'],
                        description=icon_data['description']
                    )
                    
                    # Open the image file
                    image_path = os.path.join(icons_dir, icon_data['filename'])
                    if os.path.exists(image_path):
                        with open(image_path, 'rb') as f:
                            icon.image.save(icon_data['filename'], File(f), save=True)
                        self.stdout.write(self.style.SUCCESS(f"Added {icon_data['name']}"))
                    else:
                        self.stdout.write(self.style.ERROR(f"File not found: {image_path}"))
                except Exception as e:
                    self.stdout.write(self.style.ERROR(f"Error adding {icon_data['name']}: {str(e)}"))
            else:
                self.stdout.write(f"{icon_data['name']} already exists")