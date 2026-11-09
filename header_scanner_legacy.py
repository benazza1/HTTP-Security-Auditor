#!/usr/bin/env python3
import requests
import sys
from datetime import datetime

# Codes de couleur pour le terminal
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"

def check_headers(url):
    # Ajouter le protocole si manquant
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url

    # Entete d'affichage sur le Terminal
    print(f"\n{BLUE}[*] Analyse en cours pour : {url}{RESET}\n")
    
    # Preparer le contenu du rapport textuel
    report_lines = []
    report_lines.append("="*50)
    report_lines.append(f"RAPPORT DE SECURITE - HTTP HEADERS AUDITOR")
    report_lines.append(f"Date de l'analyse : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append(f"Site cible : {url}")
    report_lines.append("="*50 + "\n")

    important_headers = {
        "Strict-Transport-Security": "Protege contre les attaques Man-in-the-Middle",
        "Content-Security-Policy": "Protege contre les injections de scripts (XSS)",
        "X-Frame-Options": "Protege contre le Clickjacking",
        "X-Content-Type-Options": "Empeche le sniffing de type MIME",
        "Referrer-Policy": "Controle les informations de referer partagees"
    }

    try:
        response = requests.get(url, timeout=10)
        headers = response.headers
        missing_count = 0
        
        for header, description in important_headers.items():
            if header in headers:
                # Affichage Terminal
                print(f"{GREEN}[✓] Present : {header}{RESET}")
                # Ecriture Rapport
                report_lines.append(f"[✓] Present : {header}")
            else:
                # Affichage Terminal
                print(f"{RED}[X] Vulnerabilite : '{header}' est manquant ! ({description}){RESET}")
                # Ecriture Rapport
                report_lines.append(f"[X] Vulnerabilite : '{header}' est manquant ! ({description})")
                missing_count += 1
                
        # Fin de l'analyse
        result_text = f"\n[!] Resultat : {missing_count} vulnerabilites trouvees sur {len(important_headers)}."
        print(f"{YELLOW}{result_text}{RESET}")
        report_lines.append(result_text)
        
        # Sauvegarde automatique dans le fichier externe
        report_filename = "scan_report.txt"
        with open(report_filename, "w") as file:
            file.write("\n".join(report_lines))
            
        print(f"\n{BLUE}[+] Le rapport externe a ete enregistre avec succes dans : {report_filename}{RESET}")
        
    except requests.exceptions.RequestException as e:
        error_text = f"[-] Erreur de connexion au site : {e}"
        print(f"{RED}{error_text}{RESET}")
        
        # Enregistrer l'erreur dans le rapport
        report_lines.append(error_text)
        with open("scan_report.txt", "w") as file:
            file.write("\n".join(report_lines))

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        target_url = input("Entrez l'URL du site a scanner (ex: google.com) : ")
        
    check_headers(target_url)

