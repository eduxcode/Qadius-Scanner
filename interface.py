import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox, scrolledtext
from scanner import load_rules, scan_file, save_report  # Adiciona save_report
from tkinter import messagebox
import threading
import os

class QadiusScannerApp:
    def __init__(self, root):
        
        self.root = root
        self.style = ttk.Style('darkly')  # Um tema escuro moderno
        self.root.title("Qadius Malware Scanner")
        self.root.geometry("600x400")
        self.root.configure(bg="#2c3e50")
        self.show_welcome_message()

        # Inicializar a variável de controle de escaneamento
        self.scan_active = False
        self.match_details = []  # Para armazenar detalhes do scan

        # Configurando grid
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)
        self.root.rowconfigure(2, weight=1)
        self.root.rowconfigure(3, weight=1)
        self.root.rowconfigure(4, weight=1)

        # Título
        self.title_label = ttk.Label(root, text="Qadius Malware Scanner", font=("Arial", 18, "bold"), bootstyle="primary")
        self.title_label.grid(row=0, column=0, pady=10, padx=20, sticky="n")

        # Botão de iniciar escaneamento
        self.scan_button = ttk.Button(root, text="Start Scan", bootstyle="success-outline", command=self.start_scan)
        self.scan_button.grid(row=1, column=0, pady=10, padx=20, sticky="n")

        # Botão de parar escaneamento
        self.stop_button = ttk.Button(root, text="Stop Scan", bootstyle="danger-outline", command=self.stop_scan, state="disabled")
        self.stop_button.grid(row=1, column=0, pady=10, padx=20, sticky="s")

        # Barra de progresso
        self.progress = ttk.Progressbar(root, orient="horizontal", length=500, mode="determinate", bootstyle="info")
        self.progress.grid(row=2, column=0, pady=20, padx=20, sticky="ew")

        # Campo de status
        self.status_label = ttk.Label(root, text="Status: Iniciar a verificação", font=("Arial", 12), bootstyle="secondary")
        self.status_label.grid(row=3, column=0, pady=10, padx=20, sticky="n")

        # Área de exibição de arquivos escaneados
        self.scan_output = scrolledtext.ScrolledText(root, width=70, height=10, wrap="word", bg="#1e282c", fg="white", insertbackground="white")
        self.scan_output.grid(row=4, column=0, pady=10, padx=20, sticky="ew")


    def show_welcome_message(self):
      """Exibe uma mensagem de boas-vindas antes do início do scanner."""
      messagebox.showinfo("Bem-vindo", "Bem-vindo ao Qadius Malware Scanner!\nSelecione um diretório para iniciar o escaneamento de malware e gerar o relatório de segurança.")

    def start_scan(self):
        # Selecionar diretório
        directory = filedialog.askdirectory()
        if directory:
            # Atualizar status
            self.status_label.config(text="Status: Escaneando...")
            self.progress["value"] = 0
            self.scan_output.delete(1.0, "end")  # Limpar área de saída
            self.scan_active = True  # Começar escaneamento
            self.scan_completed = False
            self.stop_button.config(state="normal")
            self.report_button.config(state="disabled")
            self.match_details = []  # Reiniciar os detalhes de correspondência
            
            # Carregar regras e iniciar escaneamento em uma thread separada
            thread = threading.Thread(target=self.run_scan, args=(directory,))
            thread.start()
        else:
            messagebox.showwarning("No Directory", "Selecione um diretório para verificar.")

    def stop_scan(self):
        # Parar escaneamento
        self.scan_active = False
        self.scan_completed = True 
        self.status_label.config(text="Status: Escaneamento parado")
        self.stop_button.config(state="disabled")


        # Salvar automaticamente o relatório na pasta 'reports'
        try:
            total_files = len(self.match_details)
            report_directory = "reports"
            if not os.path.exists(report_directory):
                os.makedirs(report_directory)
            self.save_and_show_report(report_directory, total_files)
        except Exception as e:
            messagebox.showerror("Erro  ao salvar relatorio", f"Ocorreu um erro ao tentar salvar o relatorio: {e}")
    
             
    def run_scan(self, directory):
        try:
            rules = load_rules("rules")
            total_files = sum([len(files) for r, d, files in os.walk(directory)])
            scanned_files = 0
    
            def scan_and_update(directory, rules):
                nonlocal scanned_files
                for root, dirs, files in os.walk(directory):
                    if not self.scan_active:
                        break
                    for file in files:
                        if not self.scan_active:
                            break
                        file_path = os.path.join(root, file)
                        matches = scan_file(file_path, rules)
                        scanned_files += 1
                        progress = (scanned_files / total_files) * 100
                        self.progress["value"] = progress
                        self.root.update_idletasks()
                        
                        # Exibe arquivo escaneado
                        self.scan_output.insert("end", f"Escaneado: {file_path}\n")
                        
                        if matches:
                            self.match_details.append((file_path, matches))
                            for rule_name, match, risk_level in matches:
                                # Exibe detalhes dos matches
                                self.scan_output.insert("end", f"Arquivo: {file_path}\nRegra: {rule_name}\nMatches: {risk_level}\n\n")
                                print(f"Arquivo: {file_path}, Regra: {rule_name}, Matches: {risk_level}")
                        
                        # Atualiza a interface a cada arquivo escaneado
                        self.root.update_idletasks()

            scan_and_update(directory, rules)
            
            if self.scan_active:
                self.status_label.config(text="Status: Scan completo")
                messagebox.showinfo("Scan Completo", "O Escaneamento foi concluído com sucesso.")
        except Exception as e:
            self.status_label.config(text=f"Status: Error - {e}")
            messagebox.showerror("Scan Error", f"Ocorreu um erro durante a verificação: {e}")

    def save_and_show_report(self, directory, total_files):
        try:
            # Salva o relatório na pasta 'reports'
            save_report(directory, total_files, len(self.match_details), self.match_details)
            messagebox.showinfo("Relatorio", f"Relatorio salvo na pasta: {directory}")
            self.status_label.config(text=f"Status: Relatorio salvo em {directory}")
        except Exception as e:
            messagebox.showerror("Erro no relatorio", f"Erro ao salavr relatorio: {e}")

if __name__ == "__main__":
    root = ttk.Window(themename="darkly")  # Utilizando o ttkbootstrap para criar a janela principal
    app = QadiusScannerApp(root)
    root.mainloop()
