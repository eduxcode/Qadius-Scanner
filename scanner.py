import yara
import os
import platform
import ctypes
import sys
from datetime import datetime
from fpdf import FPDF

# Caminho para o diretório de regras YARA
RULES_DIR = "rules/"

# Variável global para controle de escaneamento
scan_active = True

def load_rules(rules_dir):
    """Carrega todas as regras Yara do diretório especificado, ignorando regras com erros de sintaxe."""
    rules = {}
    for rule_file in os.listdir(rules_dir):
        if rule_file.endswith(".yar") or rule_file.endswith(".yara"):
            rule_path = os.path.join(rules_dir, rule_file)
            try:
                rules[rule_file] = yara.compile(filepath=rule_path)
                print(f"Carregada a regra: {rule_file}")
            except yara.SyntaxError as e:
                print(f"Erro de sintaxe na regra {rule_file}: {e} - Pulando essa regra.")
            except yara.Error as e:
                print(f"Erro geral ao carregar a regra {rule_file}: {e} - Pulando essa regra.")
    return rules

def classify_risk(match):
    """Classifica o risco baseado no conteúdo da correspondência."""
    if "entropy" in str(match):
        if "entropy_1" in str(match):
            return "Baixo risco"
        elif "entropy_2" in str(match):
            return "Médio risco"
        elif "entropy_3" in str(match):
            return "Alto risco"
    return "Desconhecido"

def scan_file(file_path, rules):
    """Escaneia um arquivo com as regras YARA carregadas e retorna as correspondências classificadas por risco."""
    matches = []
    for rule_name, rule in rules.items():
        try:
            match = rule.match(file_path)
            if match:
                risk_level = classify_risk(match)
                matches.append((rule_name, match, risk_level))
        except yara.Error as e:
            print(f"Erro ao escanear o arquivo {file_path} com a regra {rule_name}: {e}")
    return matches

def scan_directory(directory, rules, callback=None):
    """Escaneia recursivamente um diretório e reporta os arquivos suspeitos."""
    total_files = 0
    files_with_matches = 0
    match_details = []

    for root, dirs, files in os.walk(directory):
        if not scan_active:
            break
        for file in files:
            file_path = os.path.join(root, file)
            total_files += 1
            matches = scan_file(file_path, rules)
            if matches:
                files_with_matches += 1
                match_details.append((file_path, matches))
                if callback:
                    callback(file_path, matches)
    
    # Gera um relatório com os detalhes
    save_report(directory, total_files, files_with_matches, match_details)

def get_recommendation(risk_level):
        """Retorna uma recomendacao com base no nivel de risco."""
        if risk_level == "Baixo risco":
            return "Recomenda-se monitorar este arquivo regurlamente."
        elif risk_level == "Medio risco":
            return "Recomenda-se analisar este arquivo mais profundamente e considerar a remocao."
        elif risk_level == "Alto risco":
            return "Recomenda-se remover este arquivo imediatamente e investigar possíveis danos."
        else:
            return "Sem recomedacoes especificas."

def save_report(directory, total_files, files_with_matches, match_details):
    """Salva os resultados do escaneamento em um relatório PDF."""
    report_dir = "reports"
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_file = os.path.join(report_dir, f"scan_report_{timestamp}.pdf")

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Arial", "B", 16)
    pdf.cell(200, 10, txt="Relatório de Scan - Qadius Malware Scanner", ln=True, align="C")
    pdf.ln(10)

    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"Data e Hora: {timestamp}", ln=True)
    pdf.cell(200, 10, txt=f"Diretório escaneado: {directory}", ln=True)
    pdf.cell(200, 10, txt=f"Número total de arquivos escaneados: {total_files}", ln=True)
    pdf.cell(200, 10, txt=f"Número de arquivos com malware detectado: {files_with_matches}", ln=True)
    pdf.ln(10)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(200, 10, txt="Detalhes das Detecções:", ln=True)
    pdf.set_font("Arial", size=10)

    if match_details:
        for file_path, matches in match_details:
            pdf.ln(5)
            pdf.cell(200, 10, txt=f"Arquivo: {file_path}", ln=True)
            for rule_name, match, risk_level in matches:
                recommendation = get_recommendation(risk_level)
                pdf.cell(200, 10, txt=f"  - Regra: {rule_name}, Risco: {risk_level}", ln=True)
                pdf.cell(200, 10, txt=f"    Recomendacoes: {recommendation}", ln=True)
    else:
        pdf.cell(200, 10, txt="Nenhum malware detectado.", ln=True)

    try:
        pdf.output(report_file)
        print(f"Relatório salvo em: {report_file}")
    except Exception as e:
        print(f"Erro ao salvar relatório em PDF: {e}")

def check_admin():
    """Verifica se o script está sendo executado como administrador/root."""
    if platform.system() == "Windows":
        try:
            is_admin = os.getuid() == 0
        except AttributeError:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        is_admin = os.geteuid() == 0

    if not is_admin:
        print("ATENÇÃO: Execute o script como administrador para melhor funcionamento.")
        request_admin_privileges()

def request_admin_privileges():
    """Solicita privilégios de administrador se necessário."""
    if platform.system() == "Windows":
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    else:
        print("Para rodar como root, use: sudo python3 " + " ".join(sys.argv))
        sys.exit(1)

def stop_scan():
    """Interrompe o escaneamento."""
    global scan_active
    scan_active = False

if __name__ == "__main__":
    check_admin()
    rules = load_rules(RULES_DIR)

    if platform.system() == "Windows":
        scan_directory("C:\\", rules)
    else:
        scan_directory("/", rules)
