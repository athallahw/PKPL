# Create a file in your migrations folder: authorization/migrations/xxxx_add_permissions.py

from django.db import migrations

def create_custom_permissions(apps, schema_editor):
    Permission = apps.get_model('authorization', 'Permission')
    Role = apps.get_model('authorization', 'Role')
    Role_Permission = apps.get_model('authorization', 'Role_Permission')
    
    # Create permissions based on your model functionality
    permissions = [
        # Health tracking permissions
        {'id': 11, 'permission_name': 'view_health_metrics'},
        {'id': 12, 'permission_name': 'add_health_metrics'},
        {'id': 13, 'permission_name': 'edit_health_metrics'},
        
        # Point system permissions
        {'id': 14, 'permission_name': 'view_points'},
        {'id': 15, 'permission_name': 'redeem_points'},
        
        # Assessment form permissions
        {'id': 16, 'permission_name': 'view_assessment'},
        {'id': 17, 'permission_name': 'submit_assessment'},
        
        # Add all permissions you need
    ]
    
    # Create permissions
    for perm in permissions:
        Permission.objects.create(id=perm['id'], permission_name=perm['permission_name'])
    
    # Assign permissions to roles
    try:
        # Get roles
        admin_role = Role.objects.get(id=1)  # admin
        user_role = Role.objects.get(id=2)  # pengguna
        
        # Assign all permissions to admin
        for perm in Permission.objects.all():
            Role_Permission.objects.create(role=admin_role, permission=perm)
        
        # Assign user-specific permissions
        user_permission_ids = [1, 2, 3, 4, 5, 11, 12, 14, 15, 16, 17]  # IDs for permissions users should have
        for perm_id in user_permission_ids:
            perm = Permission.objects.get(id=perm_id)
            Role_Permission.objects.create(role=user_role, permission=perm)
            
    except Exception as e:
        print(f"Error assigning initial permissions: {e}")

def reverse_func(apps, schema_editor):
    # Code to reverse the migration if needed
    Permission = apps.get_model('authorization', 'Permission')
    # Delete custom permissions
    Permission.objects.filter(id__gte=11).delete()

class Migration(migrations.Migration):
    dependencies = [
        ('authorization', '0001_initial'),  # Update with your actual last migration
    ]
    
    operations = [
        migrations.RunPython(create_custom_permissions, reverse_func),
    ]