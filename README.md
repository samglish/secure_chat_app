# Messagerie chiffrée (client-side AES-GCM)

Application Flask + SQLite avec chiffrement **côté client** (Web Crypto API).  
Les messages sont stockés **uniquement chiffrés** dans la base.

## Lancer en local

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
flask --app app.py init-db
python app.py
```

Puis ouvrez http://localhost:5000

## Fonctionnalités

- Enregistrement / connexion (token simple)
- Salons (rooms) multi-utilisateurs
- Chiffrement côté client : **AES-GCM** (recommandé) ou **César** (démo)
- Stockage en base : *ciphertext* + *iv* (pour AES)
- Interface responsive, écran divisé : gauche (émetteur) / droite (récepteurs)
- Polling toutes les 2s pour récupérer les nouveaux messages

## Notes de sécurité

- Le mot de passe partagé est dérivé en clé via PBKDF2(SHA-256) avec 100k itérations, sel = nom du salon (déterministe).
- Utilisation d'AES-GCM 256 bits (Web Crypto).
- **Attention** : le modèle d'auth par token est simplifié pour un usage local/démo. Pour production, utiliser de vrais JWT/gestion de sessions, TLS, rotation des clés, etc.
