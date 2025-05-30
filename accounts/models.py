# accounts/models.py
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import RegexValidator

class CustomUser(AbstractUser):
    ROLES = (
        ('DOCTOR', 'Médecin'),
        ('NURSE', 'Infirmier'),
        ('PHARMACIST', 'Pharmacien'),
        ('ADMIN', 'Administrateur'),
        ('PATIENT', 'Patient'),
    )
    
    role = models.CharField(max_length=15, choices=ROLES)
    phone_regex = RegexValidator(
        regex=r'^\+?1?\d{9,15}$',
        message="Le numéro de téléphone doit être au format: '+221771234567'."
    )
    phone_number = models.CharField(validators=[phone_regex], max_length=17, unique=True)
    is_verified = models.BooleanField(default=False)
    mfa_code = models.CharField(max_length=6, null=True, blank=True)
    mfa_code_created_at = models.DateTimeField(null=True, blank=True)
    
    # Relations many-to-many pour éviter les conflits
    groups = models.ManyToManyField(
        'auth.Group',
        verbose_name='groups',
        blank=True,
        help_text='The groups this user belongs to.',
        related_name="customuser_set",
        related_query_name="user",
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        verbose_name='user permissions',
        blank=True,
        help_text='Specific permissions for this user.',
        related_name="customuser_set",
        related_query_name="user",
    )
    
    def __str__(self):
        return f"{self.get_full_name()} ({self.get_role_display()})"

class UserSession(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    session_key = models.CharField(max_length=40)
    created_at = models.DateTimeField(auto_now_add=True)
    logout_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        return f"Session de {self.user.username}"

class PatientRecord(models.Model):
    patient = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='medical_records')
    created_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, related_name='created_records')
    created_at = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    medical_history = models.TextField()
    allergies = models.TextField(blank=True)
    current_medications = models.TextField(blank=True)
    
    def __str__(self):
        return f"Dossier médical de {self.patient.get_full_name()}"

class Prescription(models.Model):
    patient = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='prescriptions')
    doctor = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='issued_prescriptions')
    created_at = models.DateTimeField(auto_now_add=True)
    medication = models.TextField()
    dosage = models.TextField()
    instructions = models.TextField()
    is_dispensed = models.BooleanField(default=False)
    
    def __str__(self):
        return f"Prescription pour {self.patient.get_full_name()} par Dr. {self.doctor.last_name}"

class MedicalExam(models.Model):
    EXAM_TYPES = (
        ('BLOOD', 'Analyse sanguine'),
        ('RADIO', 'Radiographie'),
        ('SCAN', 'Scanner'),
        ('OTHER', 'Autre'),
    )
    
    patient = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='exams')
    requested_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='requested_exams')
    exam_type = models.CharField(max_length=10, choices=EXAM_TYPES)
    requested_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    results = models.TextField(blank=True)
    notes = models.TextField(blank=True)
    
    def __str__(self):
        return f"{self.get_exam_type_display()} pour {self.patient.get_full_name()}"

class AuditLog(models.Model):
    ACTION_TYPES = (
        ('LOGIN', 'Connexion'),
        ('LOGOUT', 'Déconnexion'),
        ('CREATE', 'Création'),
        ('UPDATE', 'Modification'),
        ('DELETE', 'Suppression'),
        ('ACCESS', 'Accès'),
    )
    
    user = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=10, choices=ACTION_TYPES)
    model = models.CharField(max_length=50)
    object_id = models.CharField(max_length=50)
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    
    def __str__(self):
        return f"{self.user} - {self.get_action_display()} sur {self.model} à {self.timestamp}"
    
# models.py
# models.py
from django.db import models
from django.utils.translation import gettext_lazy as _

class SystemConfig(models.Model):
    class Meta:
        verbose_name = _("Configuration système")
        verbose_name_plural = _("Configurations système")

    # Paramètres Généraux
    site_name = models.CharField(max_length=100, default="Mon Application", verbose_name=_("Nom du site"))
    timezone = models.CharField(max_length=50, default="UTC", verbose_name=_("Fuseau horaire"))
    language = models.CharField(max_length=2, choices=[('fr', 'Français'), ('en', 'English')], default='fr', verbose_name=_("Langue"))
    
    # Notifications
    email_notifications = models.BooleanField(default=True, verbose_name=_("Notifications par email"))
    sms_notifications = models.BooleanField(default=False, verbose_name=_("Notifications SMS"))
    notification_email = models.EmailField(default="notifications@example.com", verbose_name=_("Email d'envoi"))

    # Sauvegarde
    class BackupFrequency(models.TextChoices):
        DAILY = 'daily', _('Quotidienne')
        WEEKLY = 'weekly', _('Hebdomadaire')
        MONTHLY = 'monthly', _('Mensuelle')
    
    backup_frequency = models.CharField(
        max_length=10,
        choices=BackupFrequency.choices,
        default=BackupFrequency.WEEKLY,
        verbose_name=_("Fréquence de sauvegarde")
    )
    backup_location = models.CharField(max_length=255, default="/backups", verbose_name=_("Emplacement de sauvegarde"))

    def __str__(self):
        return f"Configuration système - {self.site_name}"

    @classmethod
    def get_config(cls):
        """Retourne la configuration active (singleton)"""
        obj, created = cls.objects.get_or_create(pk=1)
        return obj
    


class SecuritySettings(models.Model):
    class Meta:
        verbose_name = _("Paramètre de sécurité")
        verbose_name_plural = _("Paramètres de sécurité")

    # Authentification
    mfa_enabled = models.BooleanField(default=False, verbose_name=_("MFA activé"))
    
    class MFAMethod(models.TextChoices):
        SMS = 'sms', _('SMS')
        EMAIL = 'email', _('Email')
        AUTHENTICATOR = 'authenticator', _('Application Authenticator')
    
    mfa_method = models.CharField(
        max_length=13,
        choices=MFAMethod.choices,
        default=MFAMethod.EMAIL,
        verbose_name=_("Méthode MFA")
    )
    
    # Verrouillage de compte
    max_attempts = models.PositiveIntegerField(default=5, verbose_name=_("Tentatives avant verrouillage"))
    lockout_time = models.PositiveIntegerField(default=30, verbose_name=_("Durée de verrouillage (minutes)"))

    # Politique de mot de passe
    min_length = models.PositiveIntegerField(default=8, verbose_name=_("Longueur minimale"))
    
    class ComplexityLevel(models.TextChoices):
        LOW = 'low', _('Basique (lettres seulement)')
        MEDIUM = 'medium', _('Moyenne (lettres + chiffres)')
        HIGH = 'high', _('Élevée (lettres + chiffres + spéciaux)')
    
    require_complexity = models.CharField(
        max_length=6,
        choices=ComplexityLevel.choices,
        default=ComplexityLevel.MEDIUM,
        verbose_name=_("Complexité requise")
    )
    expiry_days = models.PositiveIntegerField(default=90, verbose_name=_("Expiration après (jours)"))

    def __str__(self):
        return "Paramètres de sécurité"

    @classmethod
    def get_settings(cls):
        """Retourne les paramètres de sécurité (singleton)"""
        obj, created = cls.objects.get_or_create(pk=1)
        return obj    