import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from tkinter.ttk import Progressbar
from scanner import load_rules, scan_file, save_report  # Adiciona save_report
import threading
import os

class QadiusScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Qadius Malware Scanner")
        self.root.geometry("600x400")
        self.root.configure(bg="#2c3e50")

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
        self.title_label = tk.Label(root, text="Qadius Malware Scanner", font=("Arial", 18, "bold"), bg="#2c3e50", fg="white")
        self.title_label.grid(row=0, column=0, pady=10, padx=20, sticky="n")

        # Botão de iniciar escaneamento
        self.scan_button = tk.Button(root, text="Start Scan", font=("Arial", 14), command=self.start_scan, bg="#1abc9c", fg="white")
        self.scan_button.grid(row=1, column=0, pady=10, padx=20, sticky="n")

        # Botão de parar escaneamento
        self.stop_button = tk.Button(root, text="Stop Scan", font=("Arial", 14), command=self.stop_scan, bg="#e74c3c", fg="white")
        self.stop_button.grid(row=1, column=0, pady=10, padx=20, sticky="s")
        self.stop_button.config(state=tk.DISABLED)

        # Barra de progresso
        self.progress = Progressbar(root, orient="horizontal", length=500, mode="determinate")
        self.progress.grid(row=2, column=0, pady=20, padx=20, sticky="ew")

        # Campo de status
        self.status_label = tk.Label(root, text="Status: Iniciar a verificação", font=("Arial", 12), bg="#2c3e50", fg="white")
        self.status_label.grid(row=3, column=0, pady=10, padx=20, sticky="n")

        # Área de exibição de arquivos escaneados
        self.scan_output = scrolledtext.ScrolledText(root, width=70, height=10, wrap=tk.WORD)
        self.scan_output.grid(row=4, column=0, pady=10, padx=20, sticky="ew")

    def start_scan(self):
        # Selecionar diretório
        directory = filedialog.askdirectory()
        if directory:
            # Atualizar status
            self.status_label.config(text="Status: Escaneando...")
            self.progress["value"] = 0
            self.scan_output.delete(1.0, tk.END)  # Limpar área de saída
            self.stop_button.config(state=tk.NORMAL)
            self.scan_active = True  # Começar escaneamento
            self.match_details = []  # Reiniciar os detalhes de correspondência
            
            # Carregar regras e iniciar escaneamento em uma thread separada
            thread = threading.Thread(target=self.run_scan, args=(directory,))
            thread.start()
        else:
            messagebox.showwarning("No Directory", "Selecione um diretório para verificar.")

    def stop_scan(self):
        # Parar escaneamento
        self.scan_active = False
        self.status_label.config(text="Status: Escaneamento parado")
        self.stop_button.config(state=tk.DISABLED)

        # Salvar e mostrar o relatório parcial
        directory = filedialog.askdirectory()
        if directory:
            total_files = len(self.match_details)
            self.save_and_show_report(directory, total_files)

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
                        self.scan_output.insert(tk.END, f"Escaneado: {file_path}\n")
                        
                        if matches:
                            self.match_details.append((file_path, matches))
                            for rule_name, match, risk_level in matches:
                                # Exibe detalhes dos matches
                                self.scan_output.insert(tk.END, f"Arquivo: {file_path}\nRegra: {rule_name}\nMatches: {risk_level}\n\n")
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
            # Salva o relatório
            save_report(directory, total_files, len(self.match_details), self.match_details)
            messagebox.showinfo("Relatório", f"Relatório parcial salvo no diretório: {directory}")
            self.status_label.config(text=f"Status: Relatório salvo em {directory}")
        except Exception as e:
            messagebox.showerror("Erro no relatório", f"Erro ao salvar relatório: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = QadiusScannerApp(root)
    root.mainloop()
