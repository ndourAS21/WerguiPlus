# Generated by Django 5.2.1 on 2025-05-30 16:26

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0006_systemconfig_last_backup'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='patientrecord',
            name='id',
        ),
        migrations.RemoveField(
            model_name='systemconfig',
            name='last_backup',
        ),
        migrations.AddField(
            model_name='medicalexam',
            name='location',
            field=models.CharField(default='Laboratoire Central', max_length=100),
        ),
        migrations.AddField(
            model_name='medicalexam',
            name='status',
            field=models.CharField(choices=[('PENDING', 'En attente'), ('COMPLETED', 'Terminé'), ('CANCELLED', 'Annulé')], default='PENDING', max_length=10),
        ),
        migrations.AddField(
            model_name='medicalexam',
            name='urgency',
            field=models.CharField(choices=[('LOW', 'Faible'), ('NORMAL', 'Normal'), ('HIGH', 'Urgent'), ('CRITICAL', 'Critique')], default='NORMAL', max_length=10),
        ),
        migrations.AddField(
            model_name='patientrecord',
            name='blood_type',
            field=models.CharField(blank=True, max_length=5),
        ),
        migrations.AddField(
            model_name='patientrecord',
            name='is_protected',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='medicalexam',
            name='exam_type',
            field=models.CharField(choices=[('BLOOD', 'Analyse sanguine'), ('RADIO', 'Radiographie'), ('SCAN', 'Scanner'), ('ECG', 'Electrocardiogramme'), ('OTHER', 'Autre')], max_length=10),
        ),
        migrations.AlterField(
            model_name='patientrecord',
            name='patient',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, related_name='medical_record', serialize=False, to=settings.AUTH_USER_MODEL),
        ),
        migrations.CreateModel(
            name='Appointment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('date', models.DateField()),
                ('time', models.TimeField()),
                ('reason', models.TextField()),
                ('notes', models.TextField(blank=True)),
                ('status', models.CharField(choices=[('SCHEDULED', 'Programmé'), ('COMPLETED', 'Terminé'), ('CANCELLED', 'Annulé'), ('NO_SHOW', 'Absent')], default='SCHEDULED', max_length=20)),
                ('location', models.CharField(default='Cabinet Principal', max_length=100)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('cancellation_reason', models.TextField(blank=True)),
                ('reschedule_reason', models.TextField(blank=True)),
                ('doctor', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='doctor_appointments', to=settings.AUTH_USER_MODEL)),
                ('patient', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='patient_appointments', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
