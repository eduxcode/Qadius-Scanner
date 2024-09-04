import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from tkinter.ttk import Progressbar
from scanner import load_rules, scan_directory_multithreaded
import threading
import os

class QadiusScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Qadius Malware Scanner")
        self.root.geometry("500x350")
        self.root.configure(bg="#2c3e50")

        # Configurando grid
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)
        self.root.rowconfigure(2, weight=1)
        self.root.rowconfigure(3, weight=1)

        # Título
        self.title_label = tk.Label(root, text="Qadius Malware Scanner", font=("Arial", 18, "bold"), bg="#2c3e50", fg="white")
        self.title_label.grid(row=0, column=0, pady=10, padx=20, sticky="n")

        # Botão de iniciar escaneamento
        self.scan_button = tk.Button(root, text="Start Scan", font=("Arial", 14), command=self.start_scan, bg="#1abc9c", fg="white")
        self.scan_button.grid(row=1, column=0, pady=20, padx=20, sticky="n")

        # Barra de progresso
        self.progress = Progressbar(root, orient="horizontal", length=400, mode="determinate")
        self.progress.grid(row=2, column=0, pady=20, padx=20, sticky="ew")

        # Campo de status
        self.status_label = tk.Label(root, text="Status: Iniciar a verificação", font=("Arial", 12), bg="#2c3e50", fg="white")
        self.status_label.grid(row=3, column=0, pady=10, padx=20, sticky="s")

    def start_scan(self):
        # Selecionar diretório
        directory = filedialog.askdirectory()
        if directory:
            # Atualizar status
            self.status_label.config(text="Status: Escaneando...")
            self.progress["value"] = 0
            
            # Carregar regras e iniciar escaneamento em uma thread separada
            thread = threading.Thread(target=self.run_scan, args=(directory,))
            thread.start()
        else:
            messagebox.showwarning("No Directory", "Selecione um diretório para verificar.")

    def run_scan(self, directory):
        try:
            rules = load_rules("rules")
            total_files = sum([len(files) for r, d, files in os.walk(directory)])
            scanned_files = 0
            
            # Função customizada de scan_directory para atualizar a interface
            def scan_and_update(directory, rules):
                nonlocal scanned_files
                scan_directory_multithreaded(directory, rules, max_workers=4)
                self.status_label.config(text="Status: Scan completo")
                messagebox.showinfo("Scan Completo", "O escaneamento foi concluído com sucesso.")

            scan_and_update(directory, rules)
        except Exception as e:
            self.status_label.config(text=f"Status: Error - {e}")
            messagebox.showerror("Scan Error", f"Ocorreu um erro durante a verificação: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = QadiusScannerApp(root)
    root.mainloop()


