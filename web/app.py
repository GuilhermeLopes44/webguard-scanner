from flask import Flask, render_template, request, redirect, url_for, Response
import sys
import os
import json
import csv
import io
import requests

# Garante que o Flask consiga localizar os módulos 'core' e 'db'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from db.database import get_all_scans, init_db, get_scan_by_id, save_scan
from core.crawler import WebCrawler
from core.fuzzer import DASTFuzzer
from core.tech_detector import TechDetector
from core.passive import PassiveScanner

app = Flask(__name__)

# Inicializa o banco de dados
init_db()

@app.route('/')
def index():
    linhas = get_all_scans()
    historico_scans = []
    
    # Variáveis para o Dashboard Analítico
    total_scans = len(linhas)
    total_vulns_geral = 0
    vuln_types_count = {}
    
    for linha in linhas:
        scan_id, target, date, total, vulns_str, techs_str = linha
        
        vulns_list = json.loads(vulns_str) if vulns_str else []
        techs_list = json.loads(techs_str) if techs_str else []
        
        # Soma o total de falhas de todos os tempos
        total_vulns_geral += total
        
        # Agrupa as falhas por categoria para o Gráfico de Rosca
        for v in vulns_list:
            tipo_original = v.get('tipo', 'Outros')
            if 'XSS' in tipo_original: 
                label = 'XSS'
            elif 'SQLi' in tipo_original: 
                label = 'SQL Injection'
            elif 'Configuração' in tipo_original: 
                label = 'Security Headers'
            else: 
                label = 'Outros'
                
            vuln_types_count[label] = vuln_types_count.get(label, 0) + 1
            
        historico_scans.append({
            'id': scan_id, 
            'target': target, 
            'date': date, 
            'total': total,
            'details': vulns_list,
            'techs': techs_list
        })
        
    # Prepara os dados do gráfico no formato JSON para o JavaScript ler
    stats = {
        'total_scans': total_scans,
        'total_vulns': total_vulns_geral,
        'chart_labels': json.dumps(list(vuln_types_count.keys())),
        'chart_data': json.dumps(list(vuln_types_count.values()))
    }
        
    return render_template('index.html', scans=historico_scans, stats=stats)

@app.route('/scan', methods=['POST'])
def scan():
    target_url = request.form.get('target_url')
    
    if target_url:
        print(f"\n[*] Novo scan solicitado via Web para: {target_url}")
        
        # 1. Detectar Tecnologias
        techs = []
        try:
            r = requests.get(target_url, timeout=5)
            detector = TechDetector()
            techs = detector.detect(r.text, r.headers)
        except Exception as e:
            print(f"[!] Erro ao detectar tecnologias: {e}")

        # 2. Mapear a Superfície de Ataque
        crawler = WebCrawler(target_url)
        crawler.crawl(max_pages=3)
        
        # 3. Ataque Automatizado (DAST)
        vulns = []
        if crawler.forms_found or crawler.params_found:
            fuzzer = DASTFuzzer(crawler.forms_found, crawler.params_found)
            fuzzer.start_fuzzing()
            vulns = fuzzer.vulnerabilities
            
        # 4. Análise Passiva (Security Headers)
        passive_scanner = PassiveScanner(target_url)
        passive_vulns = passive_scanner.analyze()
        
        # Junta tudo na mesma lista
        vulns.extend(passive_vulns)
            
        # 5. Salva no banco de dados
        save_scan(target_url, vulns, techs)
        
    return redirect(url_for('index'))

@app.route('/export/<int:scan_id>')
def export_csv(scan_id):
    scan = get_scan_by_id(scan_id)
    if not scan: 
        return "Relatório não encontrado", 404
        
    scan_id, target, date, total, vulns_str, techs_str = scan
    
    vulns_list = json.loads(vulns_str) if vulns_str else []
    techs_list = json.loads(techs_str) if techs_str else []
    techs_joined = ", ".join(techs_list) if techs_list else "Não identificada"
    
    output = io.StringIO()
    writer = csv.writer(output, delimiter=';', dialect='excel')
    
    writer.writerow(['ID_Scan', 'Alvo', 'Data', 'Tecnologias', 'Tipo_Vulnerabilidade', 'URL_Afetada', 'Metodo', 'Payload_Utilizado'])
    
    if total > 0:
        for v in vulns_list:
            writer.writerow([
                scan_id, target, date, techs_joined, v['tipo'], v['url'], v.get('metodo', '-'), v['payload_utilizado']
            ])
    else:
        writer.writerow([scan_id, target, date, techs_joined, 'Seguro', '-', '-', '-'])

    response = Response(output.getvalue(), mimetype='text/csv')
    response.headers["Content-Disposition"] = f"attachment; filename=WebGuard_Scan_{scan_id}.csv"
    return response

if __name__ == '__main__':
    print("[*] Servidor WebGuard ativo em http://127.0.0.1:5000")
    app.run(debug=True, port=5000)