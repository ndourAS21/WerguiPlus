# Wergui+  Plateforme sécurisée de gestion de dossiers médicaux au Sénégal

# Contexte

Le projet Wergui+ est né d’un constat : la gestion des dossiers médicaux au Sénégal reste encore très largement manuelle, avec de nombreux risques associés, tels que la perte d’informations, les erreurs de saisie, le manque de confidentialité, ou encore la difficulté d’accès aux données pour les professionnels de santé.

L’objectif du projet est de proposer une solution numérique adaptée au contexte local, respectueuse des exigences légales en matière de protection des données personnelles, tout en étant facile à utiliser, même dans des environnements à faible connectivité.

Ce projet s’inscrit dans le cadre du module de DevSecOps, dispensé à l’École Supérieure Polytechnique de Dakar, en Master 1 Sécurité des Systèmes d’Information.

# Objectifs

- Concevoir une plateforme numérique sécurisée de gestion de dossiers médicaux
- Offrir une interface intuitive adaptée aux professionnels de santé
- Assurer la confidentialité, l’intégrité et la traçabilité des données
- Permettre l’usage du système dans des zones à connectivité réduite

# Technologies utilisées

- Backend : Python (Django, Django REST Framework, django-oauth-toolkit)
- Frontend : React.js
- Base de données : PostgreSQL
- Authentification : Authentification multifacteur (mot de passe + code SMS)
- Sécurité : chiffrement bout en bout, hachage, contrôle d’accès strict, audit
- Déploiement : GitHub, Docker (prévu), CI/CD (prévu)

# Fonctionnalités principales

- Création, consultation et mise à jour de dossiers médicaux
- Système de rôles (médecin, pharmacien, infirmier, administrateur) avec des droits distincts
- Journalisation complète et horodatée des actions (audit)
- Interface mobile-friendly, utilisable hors ligne avec synchronisation différée
- Notifications pour le suivi des traitements et des rendez-vous
- Adaptation aux contraintes locales (notamment en termes de bande passante)

## Architecture

L’architecture repose sur un modèle multi-couche, assurant une séparation claire entre les couches de présentation (React.js), de logique métier (Django) et de persistance des données (PostgreSQL). L’API est conçue selon une approche RESTful, permettant la scalabilité et la réutilisation des composants dans d’autres systèmes.

Le contrôle d’accès est géré par un système basé sur les rôles (RBAC) et renforcé par des politiques de type Mandatory Access Control (MAC), pour limiter les privilèges de chaque utilisateur aux fonctions strictement nécessaires.

# Sécurité

Le projet Wergui+ intègre dès sa conception les bonnes pratiques DevSecOps :

- **Authentification** : par identifiants + code SMS à usage unique. Sessions à durée limitée.
- **Autorisation** : accès basé sur les rôles avec filtrage granulaire des permissions.
- **Confidentialité** : chiffrement des données au repos (AES) et en transit (TLS).
- **Intégrité** : validation des entrées, hachage des données critiques, protections contre les injections SQL.
- **Auditabilité** : toutes les opérations sensibles sont journalisées et signées.
- **Conformité** : respect de la loi n° 2008-12 du 25 janvier 2008 sur la protection des données personnelles au Sénégal.

# Dépôt Git

Le code source du projet est hébergé sur GitHub :

https://github.com/ndourAS21/WeerguiPlus

Pour cloner le projet :


git clone https://github.com/ndourAS21/WeerguiPlus.git
