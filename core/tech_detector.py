import re

class TechDetector:
    def __init__(self):
        # Assinaturas comuns de tecnologias
        self.signatures = {
            "WordPress": r"wp-content|wp-includes",
            "Joomla": r"content=\"Joomla",
            "React": r"react",
            "Vue.js": r"vue",
            "Angular": r"ng-app|ng-version",
            "Bootstrap": r"bootstrap",
            "Laravel": r"laravel",
            "Django": r"django",
            "PHP": r"\.php",
            "ASP.NET": r"\.aspx|\.asp|__VIEWSTATE",
            "jQuery": r"jquery",
        }

    def detect(self, html, headers):
        detected = []
        
        # 1. Verifica Cabeçalhos (Server e X-Powered-By)
        server = headers.get('Server', '').lower()
        powered_by = headers.get('X-Powered-By', '').lower()
        
        if 'nginx' in server: detected.append("Nginx")
        if 'apache' in server: detected.append("Apache")
        if 'php' in powered_by: detected.append("PHP")
            
        # 2. Verifica o HTML por Regex
        for tech, pattern in self.signatures.items():
            if tech not in detected:
                if re.search(pattern, html, re.IGNORECASE):
                    detected.append(tech)
                    
        return list(set(detected))