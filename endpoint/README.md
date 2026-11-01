# Détection de traces de malware

Scripts **en lecture seule** (ils ne suppriment ni ne modifient rien) qui recherchent des traces de malware et écrivent un rapport sur le Bureau.

| Système | Script | Lancement |
|---|---|---|
| Windows | `Detect-Malware.ps1` | PowerShell **administrateur** : `Unblock-File .\Detect-Malware.ps1; Set-ExecutionPolicy -Scope Process Bypass -Force; .\Detect-Malware.ps1 -QuickScan` |
| macOS | `detect-malware-mac.sh` | Terminal : `chmod +x detect-malware-mac.sh && sudo ./detect-malware-mac.sh` |

Une ligne `[!]` est un point à vérifier, pas forcément un malware.
Ces scripts complètent un antivirus mais ne le remplacent pas.
