# accounts/views.py
import random
import requests
from functools import wraps
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.contrib import messages
from django.views.decorators.csrf import csrf_protect
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
from django.utils import timezone
from datetime import datetime, timedelta
from .models import (CustomUser, UserSession, PatientRecord, 
                    Prescription, MedicalExam, AuditLog)

# =============================================
# UTILITAIRES ET VUES COMMUNES
# =============================================

MFA_CODE_VALID_MINUTES = 5

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def role_required(*roles):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if request.user.role not in roles:
                messages.error(request, "Vous n'avez pas la permission d'accéder à cette page.")
                return redirect('dashboard')
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator

def home(request):
    return render(request, 'accounts/home.html')

@csrf_protect
def user_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        role = request.POST.get('role')

        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            if user.role == role:
                mfa_code = str(random.randint(100000, 999999))
                user.mfa_code = mfa_code
                user.mfa_code_created_at = datetime.now()
                user.save()

                print(f"CODE MFA POUR {user.username}: {mfa_code}")
                
                request.session['mfa_user_id'] = user.id
                return redirect('mfa_verification')
            else:
                messages.error(request, f"Rôle incorrect. Votre rôle: {user.get_role_display()}")
        else:
            messages.error(request, "Nom d'utilisateur ou mot de passe incorrect")
    
    return render(request, 'accounts/login.html')

@csrf_protect
def mfa_verification(request):
    user_id = request.session.get('mfa_user_id')
    if not user_id:
        return redirect('login')
    
    if request.method == 'POST':
        entered_code = request.POST.get('mfa_code')
        
        try:
            user = CustomUser.objects.get(id=user_id)
            
            if user.mfa_code_created_at and (timezone.now() - user.mfa_code_created_at > timedelta(minutes=5)):
                messages.error(request, "Code expiré. Veuillez vous reconnecter.")
                return redirect('login')
            
            if user.mfa_code == entered_code:
                user.mfa_code = None
                user.mfa_code_created_at = None
                user.save()
                login(request, user)
                
                UserSession.objects.create(
                    user=user,
                    session_key=request.session.session_key,
                    is_active=True
                )
                
                AuditLog.objects.create(
                    user=user,
                    action='LOGIN',
                    model='CustomUser',
                    object_id=user.id,
                    details=f"Connexion réussie via MFA",
                    ip_address=get_client_ip(request)
                )
                
                return redirect('dashboard')
            else:
                messages.error(request, "Code incorrect")
        except CustomUser.DoesNotExist:
            messages.error(request, "Session expirée")
    
    return render(request, 'accounts/mfa_verification.html')

@login_required
def user_logout(request):
    if request.user.is_authenticated:
        UserSession.objects.filter(
            user=request.user,
            session_key=request.session.session_key
        ).update(is_active=False, logout_at=timezone.now())
        
        AuditLog.objects.create(
            user=request.user,
            action='LOGOUT',
            model='CustomUser',
            object_id=request.user.id,
            details=f"Déconnexion de l'utilisateur",
            ip_address=get_client_ip(request)
        )
        
        logout(request)
        messages.success(request, "Déconnexion réussie")
    
    return redirect('home')

# =============================================
# TABLEAU DE BORD PRINCIPAL
# =============================================

@login_required
def dashboard(request):
    """Tableau de bord principal avec redirection vers les bonnes vues"""
    role_data = {
        'DOCTOR': doctor_dashboard_data(request.user),
        'NURSE': nurse_dashboard_data(request.user),
        'PHARMACIST': pharmacist_dashboard_data(request.user),
        'ADMIN': admin_dashboard_data(request.user),
        'PATIENT': patient_dashboard_data(request.user),
    }.get(request.user.role, {})
    
    context = {
        'title': role_data.get('title', 'Tableau de Bord'),
        'cards': role_data.get('cards', []),
        'user': request.user,
        'role_display': {
            'DOCTOR': '👨‍⚕️ Médecin',
            'NURSE': '👩‍⚕️ Infirmier',
            'PHARMACIST': '💊 Pharmacien',
            'ADMIN': '👔 Administrateur',
            'PATIENT': '👤 Patient'
        }.get(request.user.role, 'Utilisateur'),
        'last_login': request.user.last_login
    }
    return render(request, 'accounts/dashboard.html', context)

# Fonctions helpers pour les tableaux de bord
def doctor_dashboard_data(user):
    return {
        'title': 'Tableau de Bord Médecin',
        'stats': {
            'patients': CustomUser.objects.filter(role='PATIENT').count(),
            'prescriptions': Prescription.objects.filter(doctor=user).count()
        },
        'cards': [
            {
                'title': 'Gestion des Patients',
                'buttons': [
                    {'url': 'create_patient_record', 'text': 'Créer un dossier', 'class': 'btn-secondary'},
                    {'url': 'view_patient_records', 'text': 'Consulter un dossier', 'class': 'btn-secondary'},
                ]
            },
            {
                'title': 'Prescriptions',
                'buttons': [
                    {'url': 'create_prescription', 'text': 'Nouvelle ordonnance', 'class': 'btn-secondary'},
                    {'url': 'view_prescriptions', 'text': 'Historique des prescriptions', 'class': 'btn-primary'},
                ]
            },
            {
                'title': 'Examens Médicaux',
                'buttons': [
                    {'url': 'request_exam', 'text': 'Demander un examen', 'class': 'btn-secondary'},
                    {'url': 'view_exam_results', 'text': 'Résultats d\'examens', 'class': 'btn-primary'},
                ]
            },
            {
                'title': 'Urgences',
                'buttons': [
                    {'url': 'emergency_access', 'text': 'Accès Urgence', 'class': 'btn-emergency'},
                    {'url': 'critical_patients', 'text': 'Patients Critiques', 'class': 'btn-emergency'},
                ]
            }
        ]
    }

def nurse_dashboard_data(user):
    return {
        'title': 'Tableau de Bord Infirmier',
        'stats': {
            'vitals_today': PatientRecord.objects.filter(last_updated__date=timezone.now().date()).count()
        },
        'cards': [
            {
                'title': 'Soins aux Patients',
                'buttons': [
                    {'url': 'record_care', 'text': 'Enregistrer des soins', 'class': 'btn-secondary'},
                    {'url': 'view_patient_vitals', 'text': 'Constantes vitales', 'class': 'btn-primary'},
                ]
            },
            {
                'title': 'Prescriptions',
                'buttons': [
                    {'url': 'view_prescriptions', 'text': 'Voir les prescriptions', 'class': 'btn-secondary'},
                    {'url': 'administer_medication', 'text': 'Administrer médicament', 'class': 'btn-primary'},
                ]
            },
            {
                'title': 'Actions Rapides',
                'buttons': [
                    {'url': 'quick_vitals', 'text': 'Saisir Constantes', 'class': 'btn-primary'},
                    {'url': 'medication_administration', 'text': 'Administration Médicaments', 'class': 'btn-primary'},
                ]
            }
        ]
    }

def pharmacist_dashboard_data(user):
    return {
        'title': 'Tableau de Bord Pharmacien',
        'stats': {
            'pending_prescriptions': Prescription.objects.filter(is_dispensed=False).count(),
            'low_stock': 5  # À remplacer par une vraie requête
        },
        'cards': [
            {
                'title': 'Gestion des Médicaments',
                'buttons': [
                    {'url': 'view_prescriptions', 'text': 'Voir les prescriptions', 'class': 'btn-secondary'},
                    {'url': 'dispense_medication', 'text': 'Délivrer médicament', 'class': 'btn-primary'},
                ]
            },
            {
                'title': 'Stock Pharmacie',
                'buttons': [
                    {'url': 'view_inventory', 'text': 'Voir le stock', 'class': 'btn-secondary'},
                    {'url': 'request_reorder', 'text': 'Commander médicaments', 'class': 'btn-primary'},
                ]
            }
        ]
    }

def admin_dashboard_data(user):
    last_login = user.last_login.strftime("%d/%m/%Y %H:%M") if user.last_login else "Jamais"
    
    return {
        'title': 'Tableau de Bord Administrateur',
        'user_info': {
            'last_login': last_login,
            'role': 'Administrateur'
        },
        'cards': [
            {
                'title': 'Gestion Utilisateurs',
                'buttons': [
                    {
                        'url': 'admin:accounts_customuser_changelist',  # URL de la liste des users dans l'admin
                        'text': 'Gérer les utilisateurs', 
                        'class': 'btn-primary',
                        'icon': 'fas fa-users'
                    }
                ]
            },
            {
                'title': 'Journal d\'activité',
                'buttons': [
                    {
                        'url': 'admin:accounts_auditlog_changelist',  # URL des logs dans l'admin
                        'text': 'Voir les journaux', 
                        'class': 'btn-primary',
                        'icon': 'fas fa-clipboard-list'
                    }
                ]
            },
            {
                'title': 'Configuration',
                'buttons': [
                    {
                        'url': 'security_settings',  # Votre vue personnalisée
                        'text': 'Paramètres de sécurité', 
                        'class': 'btn-secondary',
                        'icon': 'fas fa-lock',
                        'description': 'Configurer les règles de sécurité et permissions'
                    },
                    {
                        'url': 'system_config',  # Votre vue personnalisée
                        'text': 'Configuration système', 
                        'class': 'btn-secondary',
                        'icon': 'fas fa-cog',
                        'description': 'Paramètres globaux de l\'application'
                    }
                ]
            }
        ]
    }
def patient_dashboard_data(user):
    return {
        'title': 'Mon Espace Patient',
        'stats': {
            'prescriptions': Prescription.objects.filter(patient=user).count(),
            'appointments': 0  # À remplacer par une vraie requête
        },
        'cards': [
            {
                'title': 'Mon Dossier Médical',
                'buttons': [
                    {'url': 'view_medical_record', 'text': 'Consulter mon dossier', 'class': 'btn-secondary'},
                    {'url': 'download_medical_record', 'text': 'Télécharger mon dossier', 'class': 'btn-primary'},
                ]
            },
            {
                'title': 'Mes Rendez-vous',
                'buttons': [
                    {'url': 'view_appointments', 'text': 'Mes rendez-vous', 'class': 'btn-secondary'},
                    {'url': 'book_appointment', 'text': 'Prendre rendez-vous', 'class': 'btn-primary'},
                ]
            }
        ]
    }

# =============================================
# VUES MÉDECINS
# =============================================

@login_required
@role_required('DOCTOR')
def create_patient_record(request):
    if request.method == 'POST':
        try:
            patient = CustomUser.objects.create_user(
                username=request.POST.get('username'),
                password=request.POST.get('password'),
                first_name=request.POST.get('first_name'),
                last_name=request.POST.get('last_name'),
                phone_number=request.POST.get('phone_number'),
                role='PATIENT',
                is_verified=True
            )
            
            PatientRecord.objects.create(
                patient=patient,
                created_by=request.user,
                medical_history=request.POST.get('medical_history'),
                allergies=request.POST.get('allergies'),
                current_medications=request.POST.get('current_medications')
            )
            
            AuditLog.objects.create(
                user=request.user,
                action='CREATE',
                model='PatientRecord',
                object_id=patient.id,
                details=f"Création dossier patient pour {patient.get_full_name()}",
                ip_address=get_client_ip(request)
            )
            
            messages.success(request, "Patient créé avec succès!")
            return redirect('view_patient_records')
            
        except Exception as e:
            messages.error(request, f"Erreur lors de la création: {str(e)}")
    
    return render(request, 'accounts/doctor/create_patient_record.html')

@login_required
@role_required('DOCTOR')
def view_patient_records(request):
    patients = CustomUser.objects.filter(role='PATIENT')
    records = PatientRecord.objects.select_related('patient').all()
    return render(request, 'accounts/doctor/view_patient_records.html', {
        'patients': patients,
        'records': records
    })

@login_required
@role_required('DOCTOR')
def view_patient_detail(request, patient_id):
    patient = get_object_or_404(CustomUser, id=patient_id, role='PATIENT')
    record = get_object_or_404(PatientRecord, patient=patient)
    prescriptions = Prescription.objects.filter(patient=patient)
    exams = MedicalExam.objects.filter(patient=patient)
    
    return render(request, 'accounts/doctor/view_patient_detail.html', {
        'patient': patient,
        'record': record,
        'prescriptions': prescriptions,
        'exams': exams
    })

@login_required
@role_required('DOCTOR')
def create_prescription(request):
    if request.method == 'POST':
        try:
            patient_id = request.POST.get('patient_id')
            patient = get_object_or_404(CustomUser, id=patient_id, role='PATIENT')
            
            prescription = Prescription.objects.create(
                patient=patient,
                doctor=request.user,
                medication=request.POST.get('medication'),
                dosage=request.POST.get('dosage'),
                instructions=request.POST.get('instructions')
            )
            
            record, created = PatientRecord.objects.get_or_create(patient=patient)
            if not created:
                record.current_medications += f"\n{prescription.medication} ({prescription.dosage})"
                record.save()
            
            messages.success(request, "Prescription créée avec succès!")
            return redirect('view_prescriptions')
            
        except Exception as e:
            messages.error(request, f"Erreur: {str(e)}")
    
    patients = CustomUser.objects.filter(role='PATIENT')
    return render(request, 'accounts/doctor/create_prescription.html', {
        'patients': patients,
        'medications': ['Paracétamol', 'Ibuprofène', 'Amoxicilline']
    })

@login_required
@role_required('DOCTOR')
def view_prescriptions(request):
    prescriptions = Prescription.objects.filter(doctor=request.user).select_related('patient')
    return render(request, 'accounts/doctor/view_prescriptions.html', {
        'prescriptions': prescriptions
    })

@login_required
@role_required('DOCTOR')
def request_exam(request):
    if request.method == 'POST':
        try:
            patient_id = request.POST.get('patient_id')
            patient = get_object_or_404(CustomUser, id=patient_id, role='PATIENT')
            
            exam = MedicalExam.objects.create(
                patient=patient,
                requested_by=request.user,
                exam_type=request.POST.get('exam_type'),
                notes=request.POST.get('notes')
            )
            
            AuditLog.objects.create(
                user=request.user,
                action='CREATE',
                model='MedicalExam',
                object_id=exam.id,
                details=f"Examen {exam.get_exam_type_display()} demandé pour {patient.get_full_name()}",
                ip_address=get_client_ip(request)
            )
            
            record, created = PatientRecord.objects.get_or_create(patient=patient)
            if not created:
                record.medical_history += f"\nExamen {exam.get_exam_type_display()} demandé le {timezone.now().strftime('%d/%m/%Y')}"
                record.save()
            
            messages.success(request, "Demande d'examen enregistrée!")
            return redirect('view_exam_results')
            
        except Exception as e:
            messages.error(request, f"Erreur: {str(e)}")
    
    patients = CustomUser.objects.filter(role='PATIENT')
    return render(request, 'accounts/doctor/request_exam.html', {
        'patients': patients,
        'exam_types': MedicalExam.EXAM_TYPES
    })

@login_required
@role_required('DOCTOR')
def view_exam_results(request):
    exams = MedicalExam.objects.filter(requested_by=request.user).select_related('patient')
    return render(request, 'accounts/doctor/view_exam_results.html', {
        'exams': exams
    })

@login_required
@role_required('DOCTOR')
def emergency_access(request):
    AuditLog.objects.create(
        user=request.user,
        action='ACCESS',
        model='Emergency',
        object_id=0,
        details="Accès au mode urgence activé",
        ip_address=get_client_ip(request)
    )
    return redirect('protected_records')

@login_required
@role_required('DOCTOR')
def critical_patients(request):
    critical_records = PatientRecord.objects.filter(
        medical_history__icontains='urgence'
    ).select_related('patient')
    return render(request, 'accounts/doctor/critical_patients.html', {
        'critical_patients': critical_records
    })

@login_required
@role_required('DOCTOR')
def protected_records(request):
    critical_patients = PatientRecord.objects.filter(
        medical_history__icontains='urgence'
    ).select_related('patient')
    return render(request, 'accounts/doctor/protected_records.html', {
        'critical_patients': critical_patients
    })

# =============================================
# VUES INFIRMIERS
# =============================================

@login_required
@role_required('NURSE')
def record_care(request):
    if request.method == 'POST':
        try:
            patient_id = request.POST.get('patient_id')
            patient = get_object_or_404(CustomUser, id=patient_id, role='PATIENT')
            
            record = PatientRecord.objects.get(patient=patient)
            record.medical_history += f"\n\nSoins du {timezone.now().strftime('%d/%m/%Y')}:\n"
            record.medical_history += request.POST.get('care_details')
            record.save()
            
            AuditLog.objects.create(
                user=request.user,
                action='UPDATE',
                model='PatientRecord',
                object_id=record.id,
                details=f"Soins enregistrés pour {patient.get_full_name()}",
                ip_address=get_client_ip(request)
            )
            
            messages.success(request, "Soins enregistrés avec succès!")
            return redirect('view_patient_vitals')
            
        except Exception as e:
            messages.error(request, f"Erreur: {str(e)}")
    
    patients = CustomUser.objects.filter(role='PATIENT')
    return render(request, 'accounts/nurse/record_care.html', {
        'patients': patients
    })

@login_required
@role_required('NURSE')
def view_patient_vitals(request):
    records = PatientRecord.objects.select_related('patient').all()
    return render(request, 'accounts/nurse/view_patient_vitals.html', {
        'records': records
    })

@login_required
@role_required('NURSE')
def administer_medication(request):
    if request.method == 'POST':
        try:
            prescription_id = request.POST.get('prescription_id')
            prescription = get_object_or_404(Prescription, id=prescription_id)
            
            prescription.instructions += f"\n\nAdministré le {timezone.now().strftime('%d/%m/%Y %H:%M')} par {request.user.get_full_name()}"
            prescription.save()
            
            AuditLog.objects.create(
                user=request.user,
                action='UPDATE',
                model='Prescription',
                object_id=prescription.id,
                details=f"Médicament administré à {prescription.patient.get_full_name()}",
                ip_address=get_client_ip(request)
            )
            
            messages.success(request, "Médicament administré avec succès!")
            return redirect('view_patient_vitals')
            
        except Exception as e:
            messages.error(request, f"Erreur: {str(e)}")
    
    prescriptions = Prescription.objects.filter(is_dispensed=True).select_related('patient')
    return render(request, 'accounts/nurse/administer_medication.html', {
        'prescriptions': prescriptions
    })

@login_required
@role_required('NURSE')
def quick_vitals(request):
    if request.method == 'POST':
        try:
            patient_id = request.POST.get('patient_id')
            patient = get_object_or_404(CustomUser, id=patient_id, role='PATIENT')
            
            record = PatientRecord.objects.get(patient=patient)
            record.medical_history += f"\n\nConstantes du {timezone.now().strftime('%d/%m/%Y %H:%M')}:\n"
            record.medical_history += f"TA: {request.POST.get('blood_pressure')}, "
            record.medical_history += f"Temp: {request.POST.get('temperature')}°C, "
            record.medical_history += f"Pouls: {request.POST.get('pulse')} bpm"
            record.save()
            
            AuditLog.objects.create(
                user=request.user,
                action='UPDATE',
                model='PatientRecord',
                object_id=record.id,
                details=f"Constantes vitales enregistrées pour {patient.get_full_name()}",
                ip_address=get_client_ip(request)
            )
            
            messages.success(request, "Constantes enregistrées!")
            return redirect('view_patient_vitals')
            
        except Exception as e:
            messages.error(request, f"Erreur: {str(e)}")
    
    patients = CustomUser.objects.filter(role='PATIENT')
    return render(request, 'accounts/nurse/quick_vitals.html', {
        'patients': patients
    })

@login_required
@role_required('NURSE')
def medication_administration(request):
    prescriptions = Prescription.objects.filter(is_dispensed=True).select_related('patient')
    return render(request, 'accounts/nurse/medication_administration.html', {
        'prescriptions': prescriptions
    })

# =============================================
# VUES PHARMACIENS
# =============================================

@login_required
@role_required('PHARMACIST')
def dispense_medication(request):
    if request.method == 'POST':
        try:
            prescription_id = request.POST.get('prescription_id')
            prescription = get_object_or_404(Prescription, id=prescription_id)
            
            prescription.is_dispensed = True
            prescription.save()
            
            AuditLog.objects.create(
                user=request.user,
                action='UPDATE',
                model='Prescription',
                object_id=prescription.id,
                details=f"Médicament délivré à {prescription.patient.get_full_name()}",
                ip_address=get_client_ip(request)
            )
            
            messages.success(request, "Médicament délivré avec succès!")
            return redirect('view_prescriptions')
            
        except Exception as e:
            messages.error(request, f"Erreur: {str(e)}")
    
    prescriptions = Prescription.objects.filter(is_dispensed=False).select_related('patient', 'doctor')
    return render(request, 'accounts/pharmacist/dispense_medication.html', {
        'prescriptions': prescriptions
    })

@login_required
@role_required('PHARMACIST')
def view_inventory(request):
    inventory = [
        {'name': 'Paracétamol', 'quantity': 150, 'threshold': 50},
        {'name': 'Ibuprofène', 'quantity': 80, 'threshold': 30},
        {'name': 'Amoxicilline', 'quantity': 45, 'threshold': 20},
    ]
    return render(request, 'accounts/pharmacist/view_inventory.html', {
        'inventory': inventory
    })

@login_required
@role_required('PHARMACIST')
def request_reorder(request):
    if request.method == 'POST':
        try:
            medication = request.POST.get('medication')
            quantity = request.POST.get('quantity')
            
            AuditLog.objects.create(
                user=request.user,
                action='CREATE',
                model='Reorder',
                object_id=0,
                details=f"Commande de {quantity} {medication}",
                ip_address=get_client_ip(request)
            )
            
            messages.success(request, "Commande passée avec succès!")
            return redirect('view_inventory')
            
        except Exception as e:
            messages.error(request, f"Erreur: {str(e)}")
    
    return render(request, 'accounts/pharmacist/request_reorder.html')

# =============================================
# VUES ADMINISTRATEURS
# =============================================

@login_required
@role_required('ADMIN')
def manage_users(request):
    users = CustomUser.objects.all().order_by('-date_joined')
    return render(request, 'accounts/admin/manage_users.html', {
        'users': users
    })

@login_required
@role_required('ADMIN')
def view_audit_logs(request):
    logs = AuditLog.objects.select_related('user').order_by('-timestamp')
    
    # Filtrage
    action_filter = request.GET.get('action')
    if action_filter:
        logs = logs.filter(action=action_filter)
    
    # Pagination
    page = request.GET.get('page', 1)
    paginator = Paginator(logs, 25)
    
    try:
        logs_page = paginator.page(page)
    except PageNotAnInteger:
        logs_page = paginator.page(1)
    except EmptyPage:
        logs_page = paginator.page(paginator.num_pages)
    
    return render(request, 'accounts/admin/audit_logs.html', {
        'logs': logs_page,
        'actions': AuditLog.ACTION_TYPES,
        'selected_action': action_filter
    })

# views.py
from django.contrib import messages
from .models import SystemConfig, SecuritySettings

# views.py
from django.contrib import messages
from django.utils import timezone
from .models import SystemConfig, SecuritySettings

@login_required
@role_required('ADMIN')
def system_config(request):
    config = SystemConfig.get_config()
    
    if request.method == 'POST':
        # Paramètres Généraux
        config.site_name = request.POST.get('site_name', config.site_name)
        config.timezone = request.POST.get('timezone', config.timezone)
        config.language = request.POST.get('language', config.language)
        
        # Notifications
        config.email_notifications = 'email_notifications' in request.POST
        config.sms_notifications = 'sms_notifications' in request.POST
        config.notification_email = request.POST.get('notification_email', config.notification_email)
        
        # Sauvegarde
        config.backup_frequency = request.POST.get('backup_frequency', config.backup_frequency)
        config.backup_location = request.POST.get('backup_location', config.backup_location)
        
        config.save()
        messages.success(request, "Configuration mise à jour avec succès!")
        return redirect('system_config')
    
    # Utilisez timezone.now() et les utilitaires Django plutôt que pytz
    timezones = [
        'UTC',
        'Europe/Paris',
        'America/New_York',
        'Asia/Tokyo',
        # Ajoutez d'autres fuseaux horaires selon vos besoins
    ]
    
    return render(request, 'admin/system_config.html', {
        'config': config,
        'timezones': timezones
    })

@login_required
@role_required('ADMIN')
def security_settings(request):
    settings = SecuritySettings.get_settings()
    
    if request.method == 'POST':
        # Authentification
        settings.mfa_enabled = 'mfa_enabled' in request.POST
        settings.mfa_method = request.POST.get('mfa_method', settings.mfa_method)
        
        # Verrouillage de compte
        settings.max_attempts = int(request.POST.get('max_attempts', settings.max_attempts))
        settings.lockout_time = int(request.POST.get('lockout_time', settings.lockout_time))
        
        # Politique de mot de passe
        settings.min_length = int(request.POST.get('min_length', settings.min_length))
        settings.require_complexity = request.POST.get('require_complexity', settings.require_complexity)
        settings.expiry_days = int(request.POST.get('expiry_days', settings.expiry_days))
        
        settings.save()
        messages.success(request, "Paramètres de sécurité mis à jour!")
        return redirect('security_settings')
    
    return render(request, 'admin/security_settings.html', {
        'settings': settings
    })
# =============================================
# VUES PATIENTS
# =============================================

@login_required
@role_required('PATIENT')
def view_medical_record(request):
    try:
        record = PatientRecord.objects.get(patient=request.user)
        prescriptions = Prescription.objects.filter(patient=request.user)
        exams = MedicalExam.objects.filter(patient=request.user)
        
        return render(request, 'accounts/patient/view_medical_record.html', {
            'record': record,
            'prescriptions': prescriptions,
            'exams': exams
        })
        
    except PatientRecord.DoesNotExist:
        messages.error(request, "Aucun dossier médical trouvé")
        return redirect('dashboard')

@login_required
@role_required('PATIENT')
def download_medical_record(request):
    messages.info(request, "Fonctionnalité de téléchargement en développement")
    return redirect('view_medical_record')

@login_required
@role_required('PATIENT')
def view_appointments(request):
    appointments = []  # Remplacer par Appointment.objects.filter(patient=request.user)
    return render(request, 'accounts/patient/view_appointments.html', {
        'appointments': appointments
    })

@login_required
@role_required('PATIENT')
def book_appointment(request):
    if request.method == 'POST':
        try:
            doctor_id = request.POST.get('doctor_id')
            date = request.POST.get('date')
            reason = request.POST.get('reason')
            
            AuditLog.objects.create(
                user=request.user,
                action='CREATE',
                model='Appointment',
                object_id=0,
                details=f"Rendez-vous demandé avec le docteur {doctor_id} pour le {date}",
                ip_address=get_client_ip(request)
            )
            
            messages.success(request, "Rendez-vous demandé avec succès!")
            return redirect('view_appointments')
            
        except Exception as e:
            messages.error(request, f"Erreur: {str(e)}")
    
    doctors = CustomUser.objects.filter(role='DOCTOR')
    return render(request, 'accounts/patient/book_appointment.html', {
        'doctors': doctors
    })