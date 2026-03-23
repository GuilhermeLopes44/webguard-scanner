import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs

class WebCrawler:
    def __init__(self, base_url):
        self.base_url = base_url
        self.visited_urls = set()
        self.urls_to_visit = [base_url]
        self.session = requests.Session()
        self.forms_found = []
        self.params_found = [] # NOVA LISTA: Para URLs com parâmetros (?id=1)

    def is_same_domain(self, url):
        base_domain = urlparse(self.base_url).netloc
        target_domain = urlparse(url).netloc
        return base_domain == target_domain

    def extract_links_and_params(self, url):
        """Extrai links e verifica se a própria URL possui parâmetros."""
        try:
            response = self.session.get(url, timeout=5)
            self.visited_urls.add(url)
            
            if 'text/html' not in response.headers.get('Content-Type', ''):
                return

            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 1. Busca formulários (já fazíamos)
            self.extract_forms(url, response.text)

            # 2. Busca links e parâmetros
            for link in soup.find_all('a'):
                href = link.get('href')
                if href:
                    full_url = urljoin(url, href)
                    if self.is_same_domain(full_url):
                        # Se a URL tem '?', ela tem parâmetros para atacar
                        if "?" in full_url and full_url not in [p['url'] for p in self.params_found]:
                            parsed_url = urlparse(full_url)
                            params = parse_qs(parsed_url.query)
                            self.params_found.append({
                                'url': full_url.split('?')[0],
                                'params': params
                            })
                        
                        if full_url not in self.visited_urls and full_url not in self.urls_to_visit:
                            self.urls_to_visit.append(full_url)
        except:
            pass

    def extract_forms(self, url, html_content):
        soup = BeautifulSoup(html_content, 'html.parser')
        for form in soup.find_all('form'):
            action = form.get('action')
            method = form.get('method', 'get').lower()
            action_url = urljoin(url, action) if action else url
            inputs = []
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                name = input_tag.get('name')
                if name:
                    inputs.append({'name': name, 'type': input_tag.get('type', 'text')})
            
            form_data = {'page_url': url, 'action_url': action_url, 'method': method, 'inputs': inputs}
            if form_data not in self.forms_found:
                self.forms_found.append(form_data)

    def crawl(self, max_pages=5):
        print(f"[*] Explorando: {self.base_url}")
        pages = 0
        while self.urls_to_visit and pages < max_pages:
            current_url = self.urls_to_visit.pop(0)
            if current_url not in self.visited_urls:
                self.extract_links_and_params(current_url)
                pages += 1
        return self.visited_urls