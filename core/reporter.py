import json
import os
from db.database import save_scan

class ReportGenerator:
    def __init__(self, target_url, vulnerabilities):
        self.target_url = target_url
        self.vulnerabilities = vulnerabilities

    def generate_json(self, filename="webguard_report.json"):
        report_data = {
            "target_scanned": self.target_url,
            "total_vulnerabilities_found": len(self.vulnerabilities),
            "findings": self.vulnerabilities
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=4, ensure_ascii=False)
        
        print(f"[+] Relatório JSON gerado: {os.path.abspath(filename)}")

    def save_to_db(self):
        """Nova função que chama o salvamento no banco de dados"""
        save_scan(self.target_url, self.vulnerabilities)
        print(f"[+] Resultados salvos com sucesso no Banco de Dados (webguard.db)!")