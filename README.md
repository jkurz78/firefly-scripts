# Firefly III — Scripts d'automatisation

Suite de scripts Python pour automatiser et enrichir [Firefly III](https://www.firefly-iii.org/), un gestionnaire de finances personnelles open source.

## Fonctionnalités

- **Rapport quotidien par email** — soldes des comptes, graphiques d'évolution, transactions importées, alertes fraude, catégorisation IA
- **Catégorisation IA** — utilise Claude (Anthropic) pour identifier automatiquement les marchands et catégories des transactions importées
- **Détection de fraude** — détecte les transactions inhabituelles (montants anormaux, horaires nocturnes, devises étrangères, nouveaux marchands)
- **Analyse hebdomadaire** — synthèse en français de vos dépenses par Claude
- **Validateur de transactions** — mini serveur web Flask permettant de valider d'un clic les marchands assignés par IA, directement depuis l'email

## Architecture

```
firefly_morning_report.py   — Orchestrateur du rapport quotidien
firefly_ai_categorize.py    — Catégorisation IA des transactions
firefly_fraud_detection.py  — Détection de fraude
firefly_ai_analysis.py      — Analyse hebdomadaire par IA
firefly_validator.py        — Serveur Flask de validation des marchands
firefly_trigger_import.py   — Déclenchement manuel de l'import
config.py                   — Configuration partagée (non versionnée)
docker-compose.yml          — Stack Docker complète
```

## Prérequis

- [Firefly III](https://www.firefly-iii.org/) installé et fonctionnel
- [Firefly III Data Importer](https://docs.firefly-iii.org/how-to/data-importer/installation/docker/) configuré avec Enable Banking
- Python 3.8+ sur le serveur (Synology NAS ou autre)
- Packages Python : `requests`, `matplotlib`, `Pillow`, `flask`
- Compte [Anthropic](https://www.anthropic.com/) avec clé API
- Serveur SMTP pour l'envoi des emails

## Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/votre-compte/firefly-scripts.git
cd firefly-scripts
```

### 2. Configurer

```bash
cp config.py.example config.py
```

Éditer `config.py` et remplir toutes les valeurs :
- `FIREFLY_URL` et `FIREFLY_TOKEN` — URL et Personal Access Token Firefly
- `ANTHROPIC_API_KEY` — clé API Anthropic
- `SMTP_*` — paramètres de votre serveur mail
- `VALIDATOR_SECRET` — clé secrète aléatoire (générer avec `python3 -c "import secrets; print(secrets.token_hex(32))"`)

### 3. Déployer les scripts

Copier tous les fichiers `.py` sur le serveur (ex. `/volume1/docker/firefly/`).

### 4. Déployer la stack Docker

#### 4.1 Vue d'ensemble des containers

| Container | Image | Rôle |
|---|---|---|
| `Firefly-REDIS` | `redis:7-alpine` | Cache et sessions |
| `Firefly-DB` | `postgres:16-alpine` | Base de données |
| `Firefly` | `fireflyiii/core:latest` | Application principale |
| `Firefly-Importer` | `fireflyiii/data-importer:latest` | Import interactif OAuth |
| `Firefly-Importer-Auto` | `fireflyiii/data-importer:latest` | Import automatique headless (PAT) |
| `Firefly-Cron` | `alpine:latest` | Tâches planifiées internes |
| `Firefly-Validator` | `python:3.11-slim` | Serveur de validation des marchands |

#### 4.2 Valeurs à remplacer dans docker-compose.yml

Rechercher et remplacer toutes les occurrences de :

| Placeholder | Description |
|---|---|
| `YOUR_PERSONAL_ACCESS_TOKEN` | PAT généré dans Firefly → Options → Personal Access Tokens |
| `YOUR_AUTO_IMPORT_SECRET` | Chaîne aléatoire ≥ 16 caractères — doit être identique dans `importer-auto` ET dans le container `cron` |
| `YOUR_RANDOM_32CHAR_SECRET` | Clé HMAC pour le validateur — générer avec `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `YOUR_APP_ID` | App ID Enable Banking (fourni par Enable Banking) |
| `YOUR_CLIENT_ID` | OAuth Client ID créé dans Firefly pour l'importer interactif |
| `your.smtp.host` | Serveur SMTP pour les notifications de l'importeur |
| `CHANGE_THIS_TO_A_RANDOM_16CHAR_STRING` | Même valeur que `YOUR_AUTO_IMPORT_SECRET` dans la commande cron |

#### 4.3 La clé privée Enable Banking

Enable Banking requiert une clé privée RSA pour authentifier les appels API. Le container importer attend cette clé dans la variable d'environnement `ENABLE_BANKING_PRIVATE_KEY`, mais passer une clé multi-lignes directement dans une variable d'environnement Docker est problématique.

La solution utilise `eb-entrypoint.sh` : la clé est stockée dans un fichier monté en volume, et le script d'entrée la charge dans la variable d'environnement au démarrage du container.

**Étapes :**

1. Obtenir la clé privée RSA auprès d'Enable Banking (fichier `.key` ou `.pem`)

2. La copier sur le serveur :
```bash
cp votre_cle_privee.key /volume1/docker/firefly/importer/eb_private.key
chmod 600 /volume1/docker/firefly/importer/eb_private.key
```

3. Rendre le script exécutable :
```bash
chmod +x /volume1/docker/firefly/eb-entrypoint.sh
```

4. Le `docker-compose.yml` monte automatiquement ces deux fichiers dans les containers importer :
```yaml
volumes:
  - /volume1/docker/firefly/importer/eb_private.key:/secrets/eb_private.key:ro
  - /volume1/docker/firefly/eb-entrypoint.sh:/eb-entrypoint.sh:ro
```

Au démarrage, `eb-entrypoint.sh` lit le fichier et exporte son contenu dans `ENABLE_BANKING_PRIVATE_KEY` avant de lancer l'application PHP.

#### 4.4 L'import automatique

L'import automatique fonctionne en deux temps :

**1. Container `Firefly-Importer-Auto`**

C'est une instance headless du data importer, configurée avec :
- `FIREFLY_III_ACCESS_TOKEN` — un PAT Firefly (pas d'OAuth)
- `AUTO_IMPORT_SECRET` — une chaîne secrète qui protège le endpoint HTTP de déclenchement
- `CAN_POST_AUTOIMPORT=true` — active le endpoint `/autoimport`
- `IMPORT_DIR_ALLOWLIST` — répertoire contenant les fichiers de configuration d'import (`.json`)
- `LOG_CHANNEL=single` — active l'écriture dans un fichier log (monté en volume pour le rapport du matin)

Le container expose le port `8088` uniquement en localhost (`127.0.0.1:8088:8080`), pour permettre le déclenchement manuel depuis le NAS sans l'exposer sur internet.

**2. Container `Firefly-Cron`**

Un container Alpine minimaliste qui exécute deux tâches cron :

```
0 5 * * *   → déclenche l'import Enable Banking via HTTP POST sur importer-auto
30 5 * * *  → déclenche le cron interne de Firefly (règles, tâches récurrentes, etc.)
```

Le déclenchement de l'import se fait par une simple requête HTTP vers le container importer-auto sur le réseau Docker interne :
```
http://firefly-importer-auto:8080/autoimport?secret=VOTRE_SECRET&directory=/var/www/html/storage/upload
```

⚠️ Le `secret` dans l'URL cron doit être **identique** à `AUTO_IMPORT_SECRET` dans le container `importer-auto`.

**3. Fichiers de configuration d'import**

Les fichiers `.json` de configuration Enable Banking doivent être placés dans :
```
/volume1/docker/firefly/importer/
```
Ce répertoire est monté dans les deux containers importer sous `/var/www/html/storage/upload`.

#### 4.5 Lancer la stack

```bash
docker compose up -d
```

### 5. Planifier les tâches

Configurer le planificateur de tâches du serveur :

| Heure        | Commande                                          |
|--------------|---------------------------------------------------|
| 05:00        | Déclenchement import Enable Banking (via cron Docker) |
| 05:30        | Cron interne Firefly                              |
| 06:15        | `python3 /volume1/docker/firefly/firefly_morning_report.py` |
| Dimanche 08:00 | `python3 /volume1/docker/firefly/firefly_ai_analysis.py` |

## Validator — Service de validation des marchands

Le validateur est un mini serveur Flask qui permet de cliquer sur un bouton dans l'email pour ajouter le tag `VERIFIED` à une transaction.

Les liens sont sécurisés par HMAC-SHA256 avec expiration (24h par défaut).

### Reverse proxy

Exposer le service via un reverse proxy :
```
validator.votre-domaine.com → port 8089
```

### Variables d'environnement du container

| Variable | Description |
|----------|-------------|
| `FIREFLY_URL` | URL interne Docker (ex. `http://firefly:8080`) |
| `FIREFLY_PUBLIC_URL` | URL publique (ex. `https://firefly.votre-domaine.com`) |
| `FIREFLY_TOKEN` | Personal Access Token |
| `VALIDATOR_SECRET` | Clé secrète HMAC (même valeur que dans `config.py`) |
| `VALIDATOR_TOKEN_EXPIRY_HOURS` | Durée de validité des liens (défaut: 24) |
| `VERIFIED_TAG` | Nom du tag de validation (défaut: `VERIFIED`) |

## Sécurité

- `config.py` est exclu du versionnement via `.gitignore` — ne jamais le committer
- Les clés privées (`*.key`, `*.pem`) sont également exclues
- Les liens de validation expirent après 24h et sont signés cryptographiquement

## Licence

MIT
