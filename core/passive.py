import requests

class PassiveScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
        
        # Dicionário com os cabeçalhos de segurança obrigatórios e seus respectivos riscos
        self.headers_to_check = {
            'Strict-Transport-Security': 'Falta de HSTS (Permite downgrade para HTTP)',
            'Content-Security-Policy': 'Falta de CSP (Facilita ataques de XSS)',
            'X-Frame-Options': 'Falta de X-Frame-Options (Vulnerável a Clickjacking)',
            'X-Content-Type-Options': 'Falta de Proteção contra MIME Sniffing'
        }

    def analyze(self):
        print(f"\n[*] Iniciando Análise Passiva (Headers e Cookies) em: {self.target_url}")
        try:
            # Fazemos uma única requisição para o alvo
            response = requests.get(self.target_url, timeout=5)
            headers = response.headers
            
            # 1. Auditoria de Cabeçalhos de Segurança
            for header, risk_desc in self.headers_to_check.items():
                if header not in headers:
                    self.vulnerabilities.append({
                        "tipo": f"Falha de Configuração: {risk_desc}",
                        "url": self.target_url,
                        "metodo": "GET",
                        "payload_utilizado": "Análise de Resposta (Header)"
                    })
            
            # 2. NOVA: Auditoria de Cookies (Prevenção de Session Hijacking)
            for cookie in response.cookies:
                cookie_name = cookie.name
                
                # Verifica a flag 'Secure' (impede que o cookie trafegue em conexões HTTP inseguras)
                if not cookie.secure:
                    self.vulnerabilities.append({
                        "tipo": f"Falha de Configuração: Cookie '{cookie_name}' sem flag Secure",
                        "url": self.target_url,
                        "metodo": "GET",
                        "payload_utilizado": "Análise de Cookie"
                    })
                    
                # Verifica a flag 'HttpOnly' (impede que o JavaScript/XSS roube o cookie do navegador)
                if not cookie.has_nonstandard_attr('HttpOnly') and not cookie.has_nonstandard_attr('httponly'):
                    self.vulnerabilities.append({
                        "tipo": f"Falha de Configuração: Cookie '{cookie_name}' sem flag HttpOnly (Vulnerável a XSS)",
                        "url": self.target_url,
                        "metodo": "GET",
                        "payload_utilizado": "Análise de Cookie"
                    })
                    
        except Exception as e:
            print(f"[!] Erro na análise passiva: {e}")
        
        return self.vulnerabilities