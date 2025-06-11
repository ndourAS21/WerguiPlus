# accounts/urls.py
from django.urls import path
from . import views
from .views import process_order



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
    path('doctor/view-exam-detail/<int:exam_id>/', views.view_exam_detail, name='view_exam_detail'),
    path('doctor/edit-exam/<int:exam_id>/', views.edit_exam, name='edit_exam'),
    path('doctor/delete-exam/<int:exam_id>/', views.delete_exam, name='delete_exam'),
    path('doctor/add-exam-results/<int:exam_id>/', views.add_exam_results, name='add_exam_results'),
    path('doctor/request-exam/', views.request_exam, name='request_exam'),
    path('doctor/view-exam-results/', views.view_exam_results, name='view_exam_results'),
    path('doctor/view-exam-results/', views.view_exam_results, name='view_exam_results'),
    path('doctor/emergency-access/', views.emergency_access, name='emergency_access'),
    path('doctor/critical-patients/', views.critical_patients, name='critical_patients'),
    path('doctor/view-patient-detail/<int:patient_id>/', views.view_patient_detail, name='view_patient_detail'),
    path('doctor/print-prescription/<int:prescription_id>/', views.print_prescription, name='print_prescription'),
    path('doctor/edit-prescription/<int:prescription_id>/', views.edit_prescription, name='edit_prescription'),
    path('doctor/delete-prescription/<int:prescription_id>/', views.delete_prescription, name='delete_prescription'),
    path('doctor/protected-records/', views.protected_records, name='protected_records'),
    # Infirmier
    path('nurse/record-care/', views.record_care, name='record_care'),
    path('nurse/quick-vitals/<int:patient_id>/', views.quick_vitals, name='quick_vitals'),
    path('nurse/medication-administration/', views.medication_administration, name='medication_administration'),
    path('nurse/select-patient-vitals/', views.select_patient_for_vitals, name='select_patient_vitals'),
    path('nurse/view-patient-vitals/', views.view_patient_vitals, name='view_patient_vitals'),
    path('nurse/view-patient-vitals/<int:patient_id>/', views.view_patient_vitals, name='view_patient_vitals'),
    path('nurse/administer-medication/', views.administer_medication, name='administer_medication'),
    path('nurse/administer-medication/<int:patient_id>/', views.administer_medication, name='administer_medication'),
    
    # Pharmacien
    path('pharmacist/dispense-medication/', views.dispense_medication, name='dispense_medication'),
    path('pharmacist/view-inventory/', views.view_inventory, name='view_inventory'),
    path('pharmacist/request-reorder/', views.request_reorder, name='request_reorder'),
    
    path('pharmacist/process-order/', views.process_order, name='process_order'),  # ADD THIS LINE
    path('pharmacist/view-order/<int:order_id>/', views.view_order_detail, name='view_order_detail'),
    path('pharmacist/view-orders/', views.view_orders, name='view_orders'),
    # Admin
    path('admin/manage-users/', views.manage_users, name='manage_users'),
    path('admin/security-settings/', views.security_settings, name='security_settings'),
    path('admin/system-config/', views.system_config, name='system_config'),
    path('admin/audit-logs/', views.view_audit_logs, name='view_audit_logs'),
  
    # Patient
    path('patient/view-medical-record/', views.view_medical_record, name='view_medical_record'),
    path('patient/download-medical-record/', views.download_medical_record, name='download_medical_record'),
    path('patient/view-appointments/', views.view_appointments, name='view_appointments'),
    path('patient/book-appointment/', views.book_appointment, name='book_appointment'),
    path('patient/view-medical-record/', views.view_medical_record, name='view_medical_record'),
    path('patient/download-medical-record/', views.download_medical_record, name='download_medical_record'),
    path('patient/generate-pdf-record/', views.generate_pdf_record, name='generate_pdf_record'),
    path('patient/generate-json-record/', views.generate_json_record, name='generate_json_record'),
    path('patient/generate-excel-record/', views.generate_excel_record, name='generate_excel_record'),
    path('patient/view-appointments/', views.view_appointments, name='view_appointments'),
    path('patient/book-appointment/', views.book_appointment, name='book_appointment'),
    path('patient/cancel-appointment/<int:appointment_id>/', views.cancel_appointment, name='cancel_appointment'),
    path('patient/reschedule-appointment/<int:appointment_id>/', views.reschedule_appointment, name='reschedule_appointment'),
]