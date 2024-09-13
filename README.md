# Qadius Malware Scanner 

## Visão Geral

O **Qadius Malware Scanner** é uma ferramenta para análise e detecção de malwares em arquivos usando regras YARA. Ele foi desenvolvido com Python, utilizando bibliotecas como **Tkinter** para a interface gráfica, **ttkbootstrap** para estilos modernos e **FPDF** para geração de relatórios em PDF. O scanner processa arquivos, identifica possíveis ameaças, e permite gerar um relatório com os resultados da análise.

### Funcionalidades Principais
1. Iniciar e parar escaneamento de arquivos.
2. Barra de progresso que indica o status do escaneamento.
3. Área de exibição dos resultados durante o escaneamento.
4. O relatório é salvo automaticamente na pasta reports, e o caminho é informado ao usuário.

![Qadius Scanner][Qadius app.png] 

### Pré-requisitos
Para executar o **Qadius Malware Scanner**, você precisará ter as seguintes bibliotecas e ferramentas instaladas no seu ambiente Python:

Python 3.x
- Tkinter (incluso por padrão no Python)
- ttkbootstrap (pip install ttkbootstrap)
- FPDF para geração de PDFs (pip install fpdf)

### Instalação de Dependências
Você pode instalar as dependências necessárias com os seguintes comandos:
```bash
pip install ttkbootstrap fpdf
```

## Descrição dos Componentes

**interface.py**

Este arquivo contém a lógica da interface gráfica do usuário (GUI) usando Tkinter e ttkbootstrap. A interface permite ao usuário interagir com o scanner, iniciar e parar escaneamentos, visualizar o progresso e gerar relatórios em PDF.

### Componentes da Interface:

- **Botão de Iniciar Escaneamento**: Inicia o processo de escaneamento de arquivos.
- **Botão de Parar Escaneamento**: Interrompe o escaneamento em andamento.
- **Barra de Progresso**: Indica visualmente o progresso do escaneamento.
- **Área de Texto para Resultados**: Exibe os resultados do escaneamento em tempo real.

**Funções Importantes**:

- `start_scan()`: Inicia o processo de escaneamento de arquivos.
- `stop_scan()`: Interrompe o escaneamento atual.
- `generate_report()`: Gera um relatório PDF com os resultados do escaneamento e o salva no diretório reports.

**scanner.py**

Este arquivo contém a lógica para realizar o escaneamento utilizando regras YARA. Ele processa os arquivos e retorna os resultados das correspondências encontradas com base nas regras fornecidas.

**Funções**:

- `scan_files()`: Realiza o escaneamento dos arquivos no diretório alvo usando regras YARA.
- `load_yara_rules()`: Carrega as regras YARA que serão usadas no processo de escaneamento.

**rules/**

Este diretório contém arquivos de regras **YARA** que são utilizados pelo scanner para identificar malwares e outras ameaças.

**reports/**

Os relatórios de escaneamento gerados são salvos automaticamente neste diretório, no formato PDF. O nome do arquivo segue o padrão `malware_report.pdf`.

## Como Usar o Qadius Malware Scanner

1. Inicializar a aplicação: Execute o arquivo `interface.py` para abrir a interface gráfica.
```bash
python interface.py
```

## Erros Comuns e Soluções

**1. Erro** `Tk.TclError: unknown option "-font"`:
Esse erro pode ocorrer ao usar a biblioteca *ttk*. O parâmetro `font` não deve ser passado diretamente em widgets ttk como `Button`. Use as opções nativas de estilo ou defina `font` nos widgets Tkinter padrão.

**2. Arquivo PDF não é gerado**:
Certifique-se de que a pasta `reports` existe ou que o programa tenha permissão para criar o diretório. Caso o erro persista, verifique as permissões de gravação no sistema.

# Considerações Finais

O **Qadius Malware Scanner** é um projeto extensível. Atualmente, a interface foi projetada para ser amigável e funcional, mas você pode personalizá-la e adaptá-la conforme necessário, incluindo novas funcionalidades de escaneamento, integração com outros tipos de regras, ou melhorias no design.

## Diretrizes para Contribuição

Para manter a qualidade e a consistência do código, siga estas diretrizes ao contribuir para o projeto:

- **Código Limpo e Bem Documentado**: Escreva código que seja fácil de ler e mantenha a documentação atualizada.
- **Testes**: Sempre que possível, adicione testes para as novas funcionalidades ou correções de bugs.
- **Commits Granulares**: Faça commits pequenos e focados, que sejam fáceis de entender e reverter, se necessário.
- **Respeite o Estilo do Código**: Siga o estilo de codificação PEP8 para Python e quaisquer outras convenções definidas no projeto. 