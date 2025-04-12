from django.apps import AppConfig
from django.apps import AppConfig

class AuthorizationConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'authorization'

    def ready(self):
        # Import is here to avoid AppRegistryNotReady exception
        from authorization.models import Permission, Role, Role_Permission
        
        # Only run this when the server starts, not during migrations
        import os
        if os.environ.get('RUN_MAIN') == 'true':  # Only runs once when server starts
            try:
                self.create_initial_permissions()
            except Exception as e:
                print(f"Error creating permissions: {e}")

    def create_initial_permissions(self):
        from authorization.models import Permission, Role, Role_Permission
        
        # Create permissions code here
        # Similar to the management command approach

class AuthConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'authorization'
