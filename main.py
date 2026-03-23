import argparse
from core.crawler import WebCrawler
from core.fuzzer import DASTFuzzer
from core.reporter import ReportGenerator
from db.database import init_db

def main():
    print("========================================")
    print("        WEBGUARD SCANNER - DAST         ")
    print("========================================\n")

    # 0. Inicializa o Banco de Dados
    init_db()

    parser = argparse.ArgumentParser(description="WebGuard - Scanner de Vulnerabilidades Web DAST")
    parser.add_argument("-u", "--url", required=True, help="URL alvo para escanear (ex: http://site.com)")
    args = parser.parse_args()

    target = args.url

    # 1. Módulo Crawler
    crawler = WebCrawler(target)
    crawler.crawl(max_pages=5)

    # 2. Módulo Fuzzer
    vulns = []
    if crawler.forms_found:
        fuzzer = DASTFuzzer(crawler.forms_found)
        fuzzer.start_fuzzing()
        vulns = fuzzer.vulnerabilities
    else:
        print("\n[!] Nenhum formulário encontrado para testar.")

    # 3. Módulo Reporter
    print("\n[*] Gerando relatórios...")
    reporter = ReportGenerator(target, vulns)
    reporter.generate_json()
    reporter.save_to_db() # Agora salvamos no banco!
    
    print("\n[+] Escaneamento WebGuard finalizado com sucesso!\n")

if __name__ == "__main__":
    main()