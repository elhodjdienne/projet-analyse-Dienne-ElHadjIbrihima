# Projet 1 — Analyse des journaux d'un pare-feu

**Auteur** : El Hadj Ibrihima Dienne

Analyse d'une semaine de connexions (réseau / sécurité / IoT) enregistrées par un pare-feu.

## Lancer le projet
```bash
pip install -r requirements.txt
python analyse.py
```
Le script lit `data/logs_reseau.csv`, nettoie les données, écrit `resultats.json` et enregistre les figures dans `figures/`.

## Contenu
- `analyse.py` : nettoyage, calculs, figures
- `rapport.md` : observations, comportements suspects, recommandations
- `resultats.json` : résultats générés
- `figures/` : graphiques PNG
