from django.contrib import admin
from .models import Role, Permission, Role_Permission, Pengguna, Admin, Normal

admin.site.site_header = 'PKPL Admin'
admin.site.site_title = 'PKPL Admin Portal'
admin.site.index_title = 'Welcome to PKPL Admin Portal'

# Role admin configuration
@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ('id', 'role_name')
    search_fields = ('role_name',)
    ordering = ('id',)

# Permission admin configuration
@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    list_display = ('id', 'permission_name')
    search_fields = ('permission_name',)
    ordering = ('id',)

# Role-Permission mapping admin
@admin.register(Role_Permission)
class RolePermissionAdmin(admin.ModelAdmin):
    list_display = ('role', 'permission')
    list_filter = ('role', 'permission')
    search_fields = ('role__role_name', 'permission__permission_name')

# Pengguna (User) admin
@admin.register(Pengguna)
class PenggunaAdmin(admin.ModelAdmin):
    list_display = ('id', 'email', 'role', 'get_user_type')
    list_filter = ('role',)
    search_fields = ('email',)
    
    def get_user_type(self, obj):
        if hasattr(obj, 'admin'):
            return 'Admin'
        elif hasattr(obj, 'normal'):
            return 'Normal User'
        return 'Unassigned'
    
    get_user_type.short_description = 'User Type'

# Admin user configuration
@admin.register(Admin)
class AdminUserAdmin(admin.ModelAdmin):
    list_display = ('pengguna',)
    search_fields = ('pengguna__email',)

# Normal user configuration
@admin.register(Normal)
class NormalUserAdmin(admin.ModelAdmin):
    list_display = ('pengguna', 'nama', 'poin')
    list_filter = ('gender',)
    search_fields = ('pengguna__email', 'nama', 'nama_depan', 'nama_belakang')
    fieldsets = (
        ('User Information', {
            'fields': ('pengguna',)
        }),
        ('Personal Information', {
            'fields': ('nama_depan', 'nama_belakang', 'nama', 'gender', 'tanggal_lahir', 'umur')
        }),
        ('Physical Information', {
            'fields': ('tinggi_badan',)
        }),
        ('App Data', {
            'fields': ('poin',)
        }),
    )
