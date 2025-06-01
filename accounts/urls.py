# accounts/urls.py
from django.urls import path
from . import views



urlpatterns = [
    # Authentification
    path('', views.home, name='home'),
    path('login/', views.user_login, name='login'),
    path('mfa-verification/', views.mfa_verification, name='mfa_verification'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('logout/', views.user_logout, name='logout'),
    
    # Médecin
    path('doctor/create-patient-record/', views.create_patient_record, name='create_patient_record'),
    path('doctor/view-patient-records/', views.view_patient_records, name='view_patient_records'),
    path('doctor/create-prescription/', views.create_prescription, name='create_prescription'),
    path('doctor/view-prescriptions/', views.view_prescriptions, name='view_prescriptions'),
    path('doctor/request-exam/', views.request_exam, name='request_exam'),
    path('doctor/view-exam-results/', views.view_exam_results, name='view_exam_results'),
    path('doctor/emergency-access/', views.emergency_access, name='emergency_access'),
    path('doctor/critical-patients/', views.critical_patients, name='critical_patients'),
    path('doctor/view-patient-detail/<int:patient_id>/', views.view_patient_detail, name='view_patient_detail'),
    
    # Infirmier
    path('nurse/record-care/', views.record_care, name='record_care'),
    path('nurse/view-patient-vitals/', views.view_patient_vitals, name='view_patient_vitals'),
    path('nurse/administer-medication/', views.administer_medication, name='administer_medication'),
    path('nurse/quick-vitals/', views.quick_vitals, name='quick_vitals'),
    path('nurse/medication-administration/', views.medication_administration, name='medication_administration'),
    
    # Pharmacien
    path('pharmacist/dispense-medication/', views.dispense_medication, name='dispense_medication'),
    path('pharmacist/view-inventory/', views.view_inventory, name='view_inventory'),
    path('pharmacist/request-reorder/', views.request_reorder, name='request_reorder'),
    
    path('admin/manage-users/', views.manage_users, name='manage_users'),
    path('admin/security-settings/', views.security_settings, name='security_settings'),
    path('admin/system-config/', views.system_config, name='system_config'),
    path('admin/audit-logs/', views.view_audit_logs, name='view_audit_logs'),
    
    # accounts/urls.py

    
    # Patient
    path('patient/view-medical-record/', views.view_medical_record, name='view_medical_record'),
    path('patient/download-medical-record/', views.download_medical_record, name='download_medical_record'),
    path('patient/view-appointments/', views.view_appointments, name='view_appointments'),
    path('patient/book-appointment/', views.book_appointment, name='book_appointment'),
]