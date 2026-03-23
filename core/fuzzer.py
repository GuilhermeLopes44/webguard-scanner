import requests

class DASTFuzzer:
    def __init__(self, forms_list, params_list):
        self.forms = forms_list
        self.params_urls = params_list # NOVA LISTA
        self.payloads = {
            "XSS": ["<script>alert('WebGuard')</script>", "'\"><img src=x onerror=alert(1)>"],
            "SQLi": ["'", "\"", "' OR 1=1 --", "' OR '1'='1"]
        }
        self.sql_errors = ["sql syntax", "mysql_fetch", "sqlite3.Error", "unclosed quotation mark"]
        self.session = requests.Session()
        self.vulnerabilities = []

    def start_fuzzing(self):
        # Ataque em Formulários
        for form in self.forms:
            for p_type, p_list in self.payloads.items():
                for p in p_list:
                    self.attack_form(form, p, p_type)
        
        # ATAQUE EM PARÂMETROS DE URL (GET)
        for item in self.params_urls:
            for p_type, p_list in self.payloads.items():
                for p in p_list:
                    self.attack_url_params(item, p, p_type)

    def attack_url_params(self, item, payload, vuln_type):
        url = item['url']
        params = item['params']
        
        for param_name in params:
            # Criamos uma cópia dos parâmetros e injetamos o payload em um por vez
            test_params = {k: (payload if k == param_name else v[0]) for k, v in params.items()}
            
            try:
                response = self.session.get(url, params=test_params, timeout=5)
                if self.is_vulnerable(response.text, payload, vuln_type):
                    self.vulnerabilities.append({
                        "tipo": f"{vuln_type} (URL Param)",
                        "url": response.url,
                        "metodo": "GET",
                        "payload_utilizado": payload
                    })
            except:
                pass

    def is_vulnerable(self, html, payload, vuln_type):
        if vuln_type == "XSS":
            return payload in html
        if vuln_type == "SQLi":
            return any(error in html.lower() for error in self.sql_errors)
        return False

    def attack_form(self, form, payload, vuln_type):
        # Lógica de formulário (mantida do passo anterior)
        data = {inp['name']: payload for inp in form['inputs']}
        try:
            if form['method'] == 'post':
                res = self.session.post(form['action_url'], data=data, timeout=5)
            else:
                res = self.session.get(form['action_url'], params=data, timeout=5)
            
            if self.is_vulnerable(res.text, payload, vuln_type):
                self.vulnerabilities.append({
                    "tipo": f"{vuln_type} (Form)",
                    "url": form['action_url'],
                    "metodo": form['method'].upper(),
                    "payload_utilizado": payload
                })
        except:
            pass