# 🛡️ WebGuard Scanner - DAST Tool

O **WebGuard** é uma ferramenta de **Dynamic Application Security Testing (DAST)** desenvolvida em Python para automatizar a identificação de vulnerabilidades em aplicações web.

## 🚀 Funcionalidades
- **Crawler Dinâmico:** Mapeia URLs e identifica formulários e parâmetros usando **Selenium**.
- **Fuzzer de Vulnerabilidades:** Testa entradas em tempo real contra ataques como **SQL Injection** e **XSS**.
- **Persistence & Dashboard:** Armazena resultados em SQLite e exibe em uma interface web simples em Flask.

## 🛠️ Tecnologias
- Python 3.x
- Selenium & BeautifulSoup4
- Flask & SQLite

## 📖 Como Rodar
1. Instale as dependências: `pip install -r requirements.txt`
2. Inicie o scanner: `python main.py -u http://alvo.com`