import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = 'django-insecure-votre-cle-secrete-ici'

DEBUG = True

ALLOWED_HOSTS = []

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'accounts',
    'csp',  # django-csp ajouté ici
    'axes',  # django-axes pour le verrouillage
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'csp.middleware.CSPMiddleware',  # Middleware CSP ajouté
    'axes.middleware.AxesMiddleware',  # Middleware Axes - DOIT être le dernier
]

ROOT_URLCONF = 'werguiplus.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'werguiplus.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {'min_length': 12}
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

AUTH_USER_MODEL = 'accounts.CustomUser'
LANGUAGE_CODE = 'fr-fr'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
STATICFILES_DIRS = [os.path.join(BASE_DIR, 'static')]

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Sécurité
LOGIN_URL = '/accounts/login/'


# CallMeBot




CALLMEBOT = {
    'API_KEY': "5097537",  # Votre clé
    'ENDPOINT': "https://api.callmebot.com/whatsapp.php",
    'ACTIVE': True  # Désactiver pour le développement
}

# Configuration des en-têtes de sécurité
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_BROWSER_XSS_FILTER = True

# Pour Django 3.0+
SECURE_REFERRER_POLICY = 'same-origin'

# Configuration CSP (Content Security Policy) - VERSION COMPATIBLE
CONTENT_SECURITY_POLICY = {
    'DIRECTIVES': {
        'default-src': ["'self'"],
        'script-src': ["'self'", "'unsafe-inline'", "'unsafe-eval'"],  # Ajouté pour JS dynamique
        'style-src': ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],  # Élargi pour les styles
        'img-src': ["'self'", "data:", "https:", "blob:"],  # Ajouté blob: pour les images générées
        'font-src': ["'self'", "https://fonts.gstatic.com", "data:"],  # Ajouté pour les polices web
        'connect-src': ["'self'", "https:"],  # Élargi pour les API externes
        'frame-src': ["'self'"],  # Changé de 'none' à 'self'
        'object-src': ["'none'"],
        'base-uri': ["'self'"],
        'form-action': ["'self'"],
        'media-src': ["'self'", "data:", "blob:"],  # Ajouté pour les médias
    }
}

# Configuration des cookies de session
SESSION_COOKIE_SECURE = False  # Mettre True en production avec HTTPS
SESSION_COOKIE_HTTPONLY = True  # Empêche l'accès JS
SESSION_COOKIE_SAMESITE = 'Lax'  # Protection CSRF
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

# Configuration de l'authentification
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
    'django.contrib.auth.hashers.Argon2PasswordHasher',  # Nécessite: pip install argon2-cffi
    'django.contrib.auth.hashers.BCryptSHA256PasswordHasher',  # Nécessite: pip install bcrypt
]

# Désactiver l'affichage des versions
SECURE_HIDE_SERVER_HEADERS = True

# Configuration AXES pour le verrouillage des comptes
AXES_FAILURE_LIMIT = 3  # Nombre de tentatives autorisées
AXES_COOLOFF_TIME = 1  # Temps de verrouillage en heures
AXES_RESET_ON_SUCCESS = True  # Réinitialiser le compteur après succès
AXES_LOCKOUT_TEMPLATE = 'registration/lockout.html'  # Template personnalisé
AXES_LOCKOUT_URL = '/accounts/locked/'  # URL de redirection
AXES_LOGIN_FAILURE_LIMIT = 3  # Limite pour les échecs de connexion
AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP = True  # Verrouiller par utilisateur + IP
AXES_ONLY_USER_FAILURES = False  # Pas seulement les échecs utilisateur
AXES_ENABLE_ADMIN = True  # Activer l'interface admin pour axes

# Backend d'authentification avec axes
AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',  # Backend Django par défaut
    #'axes.backends.AxesBackend',  # Backend Axes

]