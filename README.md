# ThreatHunter

Moteur de threat hunting automatisé en Python : ingestion de journaux, règles de type Sigma,
correspondance d'IOC, analyses comportementales, corrélation par hôte (ATT&CK) et rapport HTML/JSON.

## Installation
    pip install pyyaml

## Utilisation
    python -m threathunter validate rules/
    python -m threathunter hunt /chemin/logs/ --iocs iocs.txt -o rapport.html -o rapport.json
    python -m threathunter watch /chemin/logs/ --interval 300 -o rapport.html

Codes retour : 0 = rien, 1 = résultats, 2 = incident ou résultat critique (pratique en CI/SOAR).

## Entrées
- JSON / JSONL (Sysmon, EDR, Zeek, ECS), CSV, auth.log/secure (sshd, sudo)
- Les champs sont normalisés (`host`, `user`, `process`, `parent_process`, `command_line`,
  `src_ip`, `dst_ip`, `dst_port`, `dns_query`, `hashes`, `registry_key`…), les champs d'origine restent utilisables.

## Chasses
- **Règles** (`rules/*.yml`) : sous-ensemble Sigma (modificateurs contains/startswith/endswith/re/all/cidr/gt…,
  conditions and/or/not, `1 of`, `all of them`). 15 règles fournies, mappées ATT&CK.
- **IOC** : IP/CIDR, domaines (et sous-domaines), hashes MD5/SHA1/SHA256.
- **Analytiques** : beaconing réseau, brute force / password spraying, relations parent/enfant rares
  (stacking), lignes de commande obfusquées, domaines DGA / tunneling DNS.
- **Corrélation** : score de risque par hôte, incident levé quand ≥ 3 tactiques ATT&CK + une alerte haute.

## Tests
    python -m unittest discover -s tests
