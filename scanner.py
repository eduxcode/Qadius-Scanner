import yara
import os
import platform
import ctypes
import sys
from datetime import datetime

# Caminho para o diretório de regras
RULES_DIR = "rules/"

# Variáveis globais para controle de escaneamento
scan_active = True

def load_rules(rules_dir):
    """Carrega todas as regras Yara do diretório especificado."""
    rules = {}
    for rule_file in os.listdir(rules_dir):
        if rule_file.endswith(".yar") or rule_file.endswith(".yara"):
            rule_path = os.path.join(rules_dir, rule_file)
            try:
                rules[rule_file] = yara.compile(filepath=rule_path)
                print(f"Carregada a regra: {rule_file}")
            except yara.SyntaxError as e:
                print(f"Erro de sintaxe na regra {rule_file}: {e}")
    return rules

def scan_file(file_path, rules):
    """Escaneia um arquivo com as regras carregadas e retorna as correspondências."""
    matches = []
    for rule_name, rule in rules.items():
        try:
            match = rule.match(file_path)
            if match:
                matches.append((rule_name, match))
        except yara.Error as e:
            print(f"Erro ao escanear o arquivo {file_path} com a regra {rule_name}: {e}")
    return matches

def scan_directory(directory, rules, callback=None):
    """Escaneia um diretório recursivamente e reporta os arquivos suspeitos."""
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
    
    # Gerar relatório com detalhes
    save_report(directory, total_files, files_with_matches, match_details)

def save_report(directory, total_files, files_with_matches, match_details):
    """Salva os resultados do scan em um relatório detalhado."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_file = os.path.join("reports", f"scan_report_{timestamp}.txt")

    with open(report_file, "w") as report:
        report.write(f"Relatório de Scan - {timestamp}\n")
        report.write(f"Diretório escaneado: {directory}\n")
        report.write(f"Número total de arquivos escaneados: {total_files}\n")
        report.write(f"Número de arquivos com malware detectado: {files_with_matches}\n")
        report.write("\nDetalhes das Detecções:\n")

        if match_details:
            for file_path, matches in match_details:
                report.write(f"\nArquivo: {file_path}\n")
                for rule_name, match in matches:
                    report.write(f"  - Regra: {rule_name}, Matches: {[str(m) for m in match]}\n")
        else:
            report.write("Nenhum malware detectado.\n")

    print(f"Relatório salvo em: {report_file}")

def check_admin():
    """Verifica se o script está sendo executado como administrador."""
    if platform.system() == "Windows":
        try:
            is_admin = os.getuid() == 0
        except AttributeError:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        is_admin = os.geteuid() == 0

    if not is_admin:
        print("ATENÇÃO: Para melhorar as funcionalidades da ferramenta, execute o script como administrador.")
        request_admin_privileges()

def request_admin_privileges():
    """Solicita a execução do script como administrador."""
    if platform.system() == "Windows":
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    else:
        print("Para rodar o script como root, use: sudo python3 " + " ".join(sys.argv))
        sys.exit(1)

def stop_scan():
    """Para o escaneamento."""
    global scan_active
    scan_active = False

if __name__ == "__main__":
    check_admin()  # Verifica e solicita privilégios de administrador
    rules = load_rules(RULES_DIR)
    
    if platform.system() == "Windows":
        scan_directory("C:\\", rules)
    else:
        scan_directory("/", rules)
