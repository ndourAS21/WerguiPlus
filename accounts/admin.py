# accounts/admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import (CustomUser, UserSession, PatientRecord, 
                    Prescription, MedicalExam, AuditLog)

class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'first_name', 'last_name', 'role', 'is_staff', 'is_verified')
    list_filter = ('role', 'is_staff', 'is_superuser', 'is_active', 'is_verified')
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Informations personnelles', {'fields': ('first_name', 'last_name', 'email', 'phone_number')}),
        ('Rôles et permissions', {
            'fields': ('role', 'is_active', 'is_staff', 'is_superuser', 'is_verified', 'groups', 'user_permissions'),
        }),
        ('Dates importantes', {'fields': ('last_login', 'date_joined')}),
        ('MFA', {'fields': ('mfa_code', 'mfa_code_created_at')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'password1', 'password2', 'role', 'phone_number', 'is_verified'),
        }),
    )

class UserSessionAdmin(admin.ModelAdmin):
    list_display = ('user', 'created_at', 'logout_at', 'is_active')
    list_filter = ('is_active', 'user__role')
    search_fields = ('user__username', 'user__first_name', 'user__last_name')

class PatientRecordAdmin(admin.ModelAdmin):
    list_display = ('patient', 'created_by', 'created_at', 'last_updated')
    list_filter = ('created_by__role',)
    search_fields = ('patient__first_name', 'patient__last_name', 'medical_history')

class PrescriptionAdmin(admin.ModelAdmin):
    list_display = ('patient', 'doctor', 'created_at', 'is_dispensed')
    list_filter = ('doctor__role', 'is_dispensed')
    search_fields = ('patient__first_name', 'patient__last_name', 'medication')

class MedicalExamAdmin(admin.ModelAdmin):
    list_display = ('patient', 'requested_by', 'exam_type', 'requested_at', 'completed_at')
    list_filter = ('exam_type', 'requested_by__role')
    search_fields = ('patient__first_name', 'patient__last_name', 'results')

class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'action', 'model', 'timestamp', 'ip_address')
    list_filter = ('action', 'model', 'user__role')
    search_fields = ('user__username', 'details')
    readonly_fields = ('timestamp',)

admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(UserSession, UserSessionAdmin)
admin.site.register(PatientRecord, PatientRecordAdmin)
admin.site.register(Prescription, PrescriptionAdmin)
admin.site.register(MedicalExam, MedicalExamAdmin)
admin.site.register(AuditLog, AuditLogAdmin)


# accounts/admin.py
from django.contrib import admin
from .models import SecuritySettings, SystemConfig

@admin.register(SecuritySettings)
class SecuritySettingsAdmin(admin.ModelAdmin):
    list_display = ('mfa_enabled', 'mfa_method', 'max_attempts', 'require_complexity')
    fieldsets = [
        ('Authentification', {
            'fields': ('mfa_enabled', 'mfa_method'),
            'classes': ('collapse',)
        }),
        ('Verrouillage de compte', {
            'fields': ('max_attempts', 'lockout_time'),
        }),
        ('Politique de mot de passe', {
            'fields': ('min_length', 'require_complexity', 'expiry_days'),
        }),
    ]

    def has_add_permission(self, request):
        """Empêche la création de multiples instances"""
        return False if self.model.objects.count() > 0 else super().has_add_permission(request)

@admin.register(SystemConfig)
class SystemConfigAdmin(admin.ModelAdmin):
    list_display = ('site_name', 'timezone', 'language', 'backup_frequency')
    fieldsets = [
        ('Paramètres Généraux', {
            'fields': ('site_name', 'timezone', 'language'),
        }),
        ('Notifications', {
            'fields': ('email_notifications', 'sms_notifications', 'notification_email'),
            'classes': ('collapse',)
        }),
        ('Sauvegarde', {
            'fields': ('backup_frequency', 'backup_location'),
        }),
    ]

    def has_add_permission(self, request):
        """Empêche la création de multiples instances"""
        return False if self.model.objects.count() > 0 else super().has_add_permission(request)
    


from django.contrib import admin
from .models import Supplier, Medication, Order, OrderItem

@admin.register(Supplier)
class SupplierAdmin(admin.ModelAdmin):
    list_display = ['name', 'contact_email', 'delivery_time', 'shipping_cost']
    search_fields = ['name', 'contact_email']

@admin.register(Medication)
class MedicationAdmin(admin.ModelAdmin):
    list_display = ['name', 'code', 'dosage', 'stock', 'threshold', 'supplier']
    list_filter = ['supplier']
    search_fields = ['name', 'code']

admin.site.register(Order)
admin.site.register(OrderItem)    