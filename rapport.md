# Rapport d'analyse des journaux du pare-feu

**Auteur** : El Hadj Ibrihima Dienne

## Résumé
Après nettoyage (5 500 lignes brutes, 60 doublons supprimés, 166 `bytes_sent` manquants remplacés par la médiane, protocoles normalisés en majuscules), il reste **5 440 connexions** sur la semaine du 5 au 11 octobre 2026. Le trafic est dominé par HTTPS (port 443, 1 874 connexions), HTTP (1 096) et DNS (782). **13,57 %** des connexions sont bloquées (DENY). Le trafic est stable d'un jour à l'autre (environ 700 connexions/jour) sauf le **8 octobre** (1 137), jour d'un scan de ports. Deux comportements suspects ressortent nettement : un scan de ports et une exfiltration de données depuis une caméra.

## Comportement suspect 1 : scan de ports (192.168.1.99)
- Le PC `192.168.1.99` a contacté **328 ports distincts** (ports 9 à 1023) sur une seule cible, `10.0.0.5`, en **400 connexions** en seulement 15 minutes (8 octobre, 00:00 à 00:15). Toute autre IP source contacte au plus 8 ports distincts.
- **383 connexions sur 400 ont été bloquées** (DENY), mais **17 ont été autorisées** : le pare-feu laisse donc fuiter des informations sur les services ouverts.
- Figure : `figures/ports_distincts_par_ip.png` ; `figures/connexions_par_jour.png` montre le pic du 8 octobre.

## Comportement suspect 2 : exfiltration de données (192.168.1.11)
- La caméra IoT `192.168.1.11` a envoyé **environ 260 Mo** au total, alors que les autres IP source ne dépassent pas 0,63 Mo. Elle représente à elle seule près de 99 % du volume de toutes les caméras.
- **38 transferts de plus de 1 Mo** (environ 259 Mo) vers `8.8.8.8` sur le **port 8080**, tous le **10 octobre** et tous **ALLOW**, répartis sur toute la journée, y compris la nuit. Une caméra envoie normalement quelques ko par connexion (médiane ≈ 1,8 ko).
- Un port 8080 vers un résolveur DNS public est incohérent : c'est un canal probable de fuite de données (vidéo ou autre), voire un appareil compromis.
- Figures : `figures/octets_par_ip.png`, `figures/octets_par_appareil.png`.

## Recommandations de sécurité
1. **Bloquer l'IP 192.168.1.99** et l'investiguer (poste compromis ou machine de test non autorisée) ; mettre en place une règle de limitation/détection de scan (seuil de ports distincts par minute) et fermer les ports exposés inutilement sur `10.0.0.5`.
2. **Isoler la caméra 192.168.1.11** du réseau, l'analyser (firmware, mots de passe par défaut) et la réinitialiser.
3. **Segmenter les objets IoT** dans un VLAN dédié avec une politique « deny all » par défaut, n'autorisant que les flux nécessaires (par ex. MQTT 1883 vers le broker interne).
4. **Filtrer les sorties (egress)** : interdire le port 8080 et autoriser le DNS uniquement vers le résolveur interne ; ajouter une alerte sur tout volume sortant anormal (par ex. > 10 Mo par connexion).
5. **Fermer Telnet (port 23)** : 100 tentatives provenant de 29 sources, dont 26 autorisées ; utiliser SSH avec clés. Restreindre aussi RDP (3389) et SSH (22) aux postes d'administration.
