import os
import re
import tkinter as tk
from tkinter import messagebox,filedialog,ttk
from classes import Threat
from utils import *
from mitre_utils import *

# Prerequisites
# pip install tkinter

## TODO:
# - Melhoria: mostrar o nome do arquivo aberto. Pode ser no titulo da janela.
# - Melhoria: Guardar o nome e path do arquivo salvo e diferenciar Save e Save As
# - Ideia: Em cada campo de Tática/Técnica colocar um botão Detalhe que abre uma janela com o detalhamento da tatica/tecnica consultado na base
# - Ideia: Inclir botão Salvar e Exportar YAML abaixo de cada Estágio. (Vai misturar os arquivos .yml, a menos que save em um diretporio diferente)
# - Melhoria: colocar try/except nas atualizações do objeto _threar nas funçãoes add/edit para não dar erra caso o objeto tenha sido excluído antes de salvar
# - Ideia: Implementar múltiplas inclusões de autores usando separação de ;
# - Ideia: Criar um função de testar a regra de detecção (linguagem sparkSQL) em um dataset e retornar o resultado da busca.
# - Futuro:Antes de Gerar o Runbook, executar uma checagem se campos obrigatórios estão preenchidos (não se é o caso para salvar, mas é bom ter um botão de checagem dos campos)

global _locale
#Idioma usado na interface gráfica
#_locale = "pt-BR" 
_locale = "en-US" 

def app():
    #Definições
    VALIDATION_STATUS_LIST = ["unchecked", "validated", "failed","outdated"]
    DOMAIN_LIST = ["Enterprise", "Mobile", "ICS"]
    
    #Cria objetos globais do app()
    global _threat, _opened_runbook_filepath
    _threat = Threat()  # Cria o objeto global _threat.
    _opened_runbook_filepath = "" #Nome do Runbook aberto (com path)

    # Define idioma padrão
    set_locale(_locale)

    #Carrega os dados da base do MITRE ATTACK
    attck_src = get_attck_source_from_local_json("mitre/enterprise-attack.json")
    
    # Cria a janela principal
    root = tk.Tk()
    root.title("Runbook Creator/Editor - v1.1")

    # Geometria da janela
    #largura = 1024
    #altura = 700
    #x = (root.winfo_screenwidth() - largura) / 2
    #y = (root.winfo_screenheight() - altura) / 2
    #root.geometry(f"{largura}x{altura}+{int(x)}+{int(y)}")
    root.geometry(f"1024x768+0+0")

    # Definição de fonte
    root.option_add("*Font", "Arial 10")

    #### Funções do Menu ####
    def new_runbook():
        answer = messagebox.askokcancel(
            "Descartar Runbook",
            "O Runbook aberto será descartado. Tem certeza?"
        )
        if answer:
            global _threat, _opened_runbook_filepath
            _threat = Threat() #Zera o objeto Threat
            _opened_runbook_filepath = ""
            clear_all_fields() #Limpa os campos
            threat_id_entry.configure(state="normal")
            threat_id_entry.insert(0,generate_key("THR")) #Gera um novo Threat ID
            threat_id_entry.configure(state="readonly")
            creation_date_entry.configure(state="normal")
            creation_date_entry.insert(0, get_today_date())
            creation_date_entry.configure(state="readonly")
            
    def open_runbook():
        """
        Abre um popup para selecionar o arquivo YAML e carrega o runbook.
        """
        answer = messagebox.askokcancel(
            "Abrir Runbook",
            "Dados não salvos serão descartados. Deseja continuar?"
        )
        if not answer:
            return
        initial_path = os.path.join(os.getcwd(),"runbooks") #Preferencialmente procurar no diretório 'runbooks'
        if not os.path.isdir(initial_path):
            initial_path = os.getcwd()
        filepath = filedialog.askopenfilename(
            initialdir=initial_path,
            title="Selecione o arquivo YAML",
            filetypes=(("Arquivos YAML", "*.yml"), ("Todos os arquivos", "*.*"))
        )
        if filepath:
            try:
                global _threat, _opened_runbook_filepath
                _threat = load_runbook_from_file(filepath) #Carrega os dados do runbook no objeto Threat
                _opened_runbook_filepath = filepath
                load_threat_data() #Carrega os dados do objeto Threat nos campos da interface gráfica
                #messagebox.showinfo("Sucesso", "Runbook carregado com sucesso!")
            except Exception as e:
                messagebox.showerror("Erro", f"Erro ao carregar o runbook: {e}")

        # Inicia o loop da interface gráfica
        root.mainloop()

    def save_runbook():
        answer = messagebox.askokcancel(
            "Salvar Runbook",
            "O Runbook será consolidado e salvo em forma de YAML. Tem certeza?"
        )
        if answer:
            #Threat_id
            if not threat_id_entry.get():
                threat_id_entry.configure(state="normal")
                threat_id_entry.insert(0,generate_key("THR"))
                threat_id_entry.configure(state="readonly")
            #data criação
            if not creation_date_entry.get():
                creation_date_entry.configure(state="normal")
                creation_date_entry.insert(0,get_today_date())
                creation_date_entry.configure(state="readonly")
            #Atualiza update_date
            update_date_entry.configure(state="normal")
            update_date_entry.delete(0,tk.END)
            update_date_entry.insert(0,get_today_date())
            update_date_entry.configure(state="readonly")
            #Salvar campos
            save_threat_fields()
            initial_path = os.path.join(os.getcwd(),"runbooks") #Preferencialmente abrir no diretório 'runbooks'
            if not os.path.isdir(initial_path):
                try:
                    os.mkdir(initial_path)
                except OSError as e:
                    #messagebox.showerror("Erro", f"Erro ao criar diretório {initial_path}: {e}")
                    initial_path = os.getcwd()
            #Escolher local e nome do arquivo
            file_path = filedialog.asksaveasfilename(
                initialdir=initial_path,
                title="Salvar Runbook",
                filetypes=(("Runbook", "*.yml"), ("All Files", "*.*")),
                defaultextension=".yml"
            )
            if not file_path:
                return
            if not file_path.endswith(".yml"):
                file_path += ".yml"
            #Salvar o runbook
            try:
                save_runbook_to_file(_threat,file_path)
                nome_arquivo = os.path.basename(file_path)
                messagebox.showinfo("Sucesso", "Runbook " + nome_arquivo + " salvo com sucesso!")
            except Exception as e:
                messagebox.showerror("Erro", f"Erro ao salvar o runbook: {e}")

    def view_threat():
        #Função para printar os dados
        def print_threat_data():
            #save_threat_fields()
            print_threat_text_area(_threat, text_area)
        #Cria janela
        view_window = tk.Toplevel(root)
        view_window.transient(root) # Faz com que a janela seja filha da janela principal
        view_window.title("Visuzalizar Dados da Threat")
        view_window.geometry(f"400x400+{root.winfo_x()+100}+{root.winfo_y()+100}")
        #Conteúdo
        content_frame = tk.Frame(view_window)
        content_frame.pack(fill="both", expand=True, padx=10, pady=5)
        text_area = tk.Text(content_frame, wrap=tk.WORD, width=20, height=5)
        text_area.pack(side="left", fill="both", expand=True)
        text_area.configure(state="disabled")
        vscrollbar = tk.Scrollbar(content_frame, orient="vertical", command=text_area.yview)
        vscrollbar.pack(side="right", fill="y")
        text_area.configure(yscrollcommand=vscrollbar.set)
        #Botões
        action_frame = tk.Frame(view_window)
        action_frame.pack(side="bottom", padx=10, pady=(5,10))
        tk.Button(action_frame, text="Refresh", command=print_threat_data).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Fechar", command=view_window.destroy).grid(row=0, column=1, padx=10, sticky="w")
        #Execução inicial
        print_threat_data()
    
    def keygen_tool():
        #Função para gerar as chaves
        def write_key(key_type):
            keygen_window.focus_set()
            field_mapping = {
                "THR": threat_key_entry,
                "REF": reference_key_entry,
                "TTP": ttp_key_entry,
                "DTR": detection_rule_key_entry
            }
            entry = field_mapping[key_type]
            entry.delete(0, tk.END)
            entry.insert(0, generate_key(key_type))
        #Cria janela
        keygen_window = tk.Toplevel(root)
        keygen_window.title(t("Gerador de Chaves"))
        keygen_window.geometry(f"350x160+{root.winfo_x()+100}+{root.winfo_y()+100}")
        # Cria os campos
        tk.Label(keygen_window, text="Threat").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        threat_key_entry = tk.Entry(keygen_window, width=25)
        threat_key_entry.grid(row=0, column=1, sticky="e", padx=5, pady=5)
        tk.Button(keygen_window, text="Gerar", command=lambda: write_key("THR")).grid(row=0, column=2, sticky="e", padx=5, pady=5)

        tk.Label(keygen_window, text="Reference").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        reference_key_entry = tk.Entry(keygen_window, width=25)
        reference_key_entry.grid(row=1, column=1, sticky="e", padx=5, pady=5)
        tk.Button(keygen_window, text="Gerar", command=lambda: write_key("REF")).grid(row=1, column=2, sticky="e", padx=5, pady=5)

        tk.Label(keygen_window, text="TTP").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        ttp_key_entry = tk.Entry(keygen_window, width=25)
        ttp_key_entry.grid(row=2, column=1, sticky="e", padx=5, pady=5)
        tk.Button(keygen_window, text="Gerar", command=lambda: write_key("TTP")).grid(row=2, column=2, sticky="e", padx=5, pady=5)

        tk.Label(keygen_window, text="Detection Rule").grid(row=3, column=0, sticky="w", padx=5, pady=5)
        detection_rule_key_entry = tk.Entry(keygen_window, width=25)
        detection_rule_key_entry.grid(row=3, column=1, sticky="e", padx=5, pady=5)
        tk.Button(keygen_window, text="Gerar", command=lambda: write_key("DTR")).grid(row=3, column=2, sticky="e", padx=5, pady=5)

    ###########################

    # Cria o menu
    menubar = tk.Menu(root)
    filemenu = tk.Menu(menubar, tearoff=0)
    filemenu.add_command(label="Novo Runbook", command=new_runbook)
    filemenu.add_command(label="Abrir Runbook", command=open_runbook)
    filemenu.add_command(label="Salvar Runbook", command=save_runbook)
    filemenu.add_separator()
    filemenu.add_command(label="Sair", command=root.quit)
    menubar.add_cascade(label=t("Arquivo"), menu=filemenu)
    toolmenu = tk.Menu(menubar, tearoff=0)
    toolmenu.add_command(label="Ver Threat", command=view_threat)
    toolmenu.add_command(label="Keygen", command=keygen_tool)
    menubar.add_cascade(label=t("Ferramentas"), menu=toolmenu)
    root.config(menu=menubar)

    #### Estrutura do root ####
    # Canvas principal com barra de rolagem H e V
    canvas_root = tk.Canvas(root)
    vscrollbar_root = tk.Scrollbar(root, orient="vertical", command=canvas_root.yview)
    #hscrollbar_root = tk.Scrollbar(root, orient="horizontal", command=canvas_root.xview)
    canvas_root.configure(yscrollcommand=vscrollbar_root.set)
    #canvas_root.configure(xscrollcommand=hscrollbar_root.set)
    canvas_root.grid(row=0, column=0, sticky="nsew")
    vscrollbar_root.grid(row=0, column=1, sticky="ns")
    #hscrollbar_root.grid(row=1, column=0, sticky="ew")
    root.grid_columnconfigure(0, weight=1)
    root.grid_rowconfigure(0, weight=1)
    
    # Frame para incluir os 4 labelframe
    frame_root = tk.Frame(canvas_root)
    canvas_root.create_window((0, 0), window=frame_root, anchor='nw')
    # Incluindo os 4 labelframe ao frame
    # Divisão em 4 Estágios
    stage1_frame = tk.LabelFrame(frame_root, text=t(" ESTÁGIO 1 - Mapeamento Ameaça-TTP "), font=("Arial", 10, "bold"), relief="solid", borderwidth=1)
    stage1_frame.pack(padx=10, pady=5, fill="both", expand=True)

    stage2_frame = tk.LabelFrame(frame_root, text=t(" ESTÁGIO 2 - Mapeamento TTP-Dados "), font=("Arial", 10, "bold"), relief="solid", borderwidth=1)
    stage2_frame.pack(padx=10, pady=5, fill="both", expand=True)

    stage3_frame = tk.LabelFrame(frame_root, text=t(" ESTÁGIO 3 - Validação "), font=("Arial", 10, "bold"), relief="solid", borderwidth=1)
    stage3_frame.pack(padx=10, pady=5, fill="both", expand=True)

    stage4_frame = tk.LabelFrame(frame_root, text=t(" ESTÁGIO 4 - Consolidação dos Resultados "), font=("Arial", 10, "bold"), relief="solid", borderwidth=1)
    stage4_frame.pack(padx=10, pady=5, fill="x", expand=False)
    ###########################
    
    
    #### Estrutura do stage1_frame ####

    threat_frame = tk.Frame(stage1_frame)
    threat_frame.pack(fill="x",)
    references_frame = tk.Frame(stage1_frame)
    references_frame.pack(fill="x", pady=20)
    ttps_frame = tk.Frame(stage1_frame)
    ttps_frame.pack(fill="x", pady=(0,5))


    #### Funções de Botões do threat_frame ####
    def generate_threat_id():
        new_id = generate_key("THR")
        threat_id_entry.configure(state="normal")
        threat_id_entry.delete(0, tk.END)
        threat_id_entry.insert(0, new_id)
        threat_id_entry.configure(state="readonly")
        _threat.threat_id = new_id
        
    def add_platform():
        """
        Abre uma janela para inserir uma nova plataforma no listbox.
        """
        def add(event=None):
            new_platform = platform_entry.get().strip()
            #Check campo vazio
            if not new_platform:
                messagebox.showerror("Erro", "A plataforma não pode ser vazia.")
                return
            #Check duplicidade
            if new_platform in platforms_listbox.get(0, tk.END):
                messagebox.showerror("Erro", "A plataforma ja existe.")
                return
            #Adiciona na lista
            platforms_listbox.insert(tk.END, new_platform)
            _threat.platforms.append(new_platform)
            add_window.destroy()

        #Cria a janela
        add_window = tk.Toplevel(root)
        add_window.geometry(f"300x100+{root.winfo_x()+100}+{root.winfo_y()+100}")
        add_window.title("Incluir Plataforma")
        #Content Frame
        content_frame = tk.Frame(add_window)
        content_frame.pack(fill="both", expand=True, padx=20, pady=5)
        tk.Label(content_frame, text="Platform").pack(side="left", padx=10)
        platform_entry = tk.Entry(content_frame)
        platform_entry.pack(side="left", padx=10, fill="x", expand=True)
        platform_entry.bind("<Return>", add)
        platform_entry.focus_set()
        #Action Frame
        action_frame = tk.Frame(add_window)
        action_frame.pack(side="bottom", padx=20, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=add_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Incluir", command=add).grid(row=0, column=1, padx=10, sticky="w")
    
    def edit_platform():
        selected_index = platforms_listbox.curselection()
        if not selected_index:
            return
        selected_platform = platforms_listbox.get(selected_index)
        
        def save(event=None):
            new_platform = platform_entry.get().strip()
            #Check campo vazio
            if not new_platform:
                messagebox.showerror("Erro", "A plataforma não pode ser vazia.")
                return
            #Check duplicidade
            if new_platform in platforms_listbox.get(0, tk.END):
                messagebox.showerror("Erro", "A plataforma ja existe.")
                return
            #Substitui na lista
            platforms_listbox.delete(selected_index)
            platforms_listbox.insert(selected_index, new_platform)
            idx_platform = _threat.platforms.index(selected_platform)
            _threat.platforms[idx_platform] = new_platform
            edit_window.destroy()

        def delete():
            if messagebox.askyesno("Excluir", "Deseja excluir esta plataforma?"):
                #Remove da lista
                platforms_listbox.delete(selected_index)
                _threat.platforms.remove(selected_platform)
                edit_window.destroy()
            else:
                edit_window.lift()

        #Cria a janela de edição
        edit_window = tk.Toplevel(root)
        edit_window.geometry(f"300x100+{root.winfo_x()+100}+{root.winfo_y()+100}")
        edit_window.title("Editar Plataforma")
        #Content Frame
        content_frame = tk.Frame(edit_window)
        content_frame.pack(fill="both", expand=True, padx=20, pady=5)
        tk.Label(content_frame, text="Platform").pack(side="left", padx=10)
        platform_entry = tk.Entry(content_frame)
        platform_entry.insert(0, selected_platform)
        platform_entry.pack(side="left", padx=10, fill="x", expand=True)
        platform_entry.bind("<Return>", save)
        platform_entry.focus_set()
        #Action Frame
        action_frame = tk.Frame(edit_window)
        action_frame.pack(side="bottom", padx=20, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=edit_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Salvar", command=save).grid(row=0, column=1, padx=10, sticky="ew")
        tk.Button(action_frame, text="Excluir", command=delete).grid(row=0, column=2, padx=10, sticky="w")
    

    def edit_description():
        #Pega description inicial da Threat
        initial_description = description_text.get("1.0", tk.END).rstrip("\n")

        #Função para salvar nota da TTP
        def save(event=None):
            new_description = w_description_text.get("1.0", tk.END).rstrip("\n").strip()
            # Atualiza dados  no objeto _threat
            _threat.description = new_description
            # Atualiza textarea no app
            description_text.delete("1.0", tk.END)
            description_text.insert(tk.INSERT, new_description)
            edit_window.destroy()
        
        def delete():
            if messagebox.askyesno("Excluir", "Deseja excluir esta Descrição?"):
                # Atualiza dados no objeto _threat
                _threat.description = ''
                # Atualiza textarea no app
                description_text.delete("1.0", tk.END)
                edit_window.destroy()
            else:
                edit_window.lift()

        #Cria a janela de edição
        edit_window = tk.Toplevel(root)
        edit_window.geometry(f"500x300+{root.winfo_x()+100}+{root.winfo_y()+100}")
        edit_window.title("Editar Descrição da Threat")
        #Content Frame
        content_frame = tk.Frame(edit_window)
        content_frame.pack(fill="both", expand=True, padx=5, pady=5)
        content_frame.columnconfigure(1, weight=1)
        content_frame.rowconfigure(2, weight=1)
        #Column0
        tk.Label(content_frame, text="Descrição").grid(row=0, column=0, sticky="nw", padx=10)
        tk.Button(content_frame, text="Juntar Linhas", command=lambda: join_lines(w_description_text)).grid(row=1, column=0, sticky="nw", padx=10, pady=10)
        tk.Button(content_frame, text="Separar Frases", command=lambda: separate_phrases(w_description_text)).grid(row=2, column=0, sticky="nw", padx=10)
        #Column1
        w_description_text = tk.Text(content_frame, width=20, height=5)
        w_description_text.insert(tk.END, initial_description)
        w_description_text.grid(row=0, column=1, rowspan=3, sticky="nsew", padx=(5,0))
        w_description_text.bind("<Control-Return>", save)
        w_description_text.focus_set()
        #Column2
        w_description_text_scrollbar = tk.Scrollbar(content_frame, orient="vertical", command=w_description_text.yview)
        w_description_text_scrollbar.grid(row=0, column=2, rowspan=3, sticky="ns", padx=(0,5))
        w_description_text.configure(yscrollcommand=w_description_text_scrollbar.set)
        #Action Frame
        action_frame = tk.Frame(edit_window)
        action_frame.pack(side="bottom", padx=5, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=edit_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Salvar", command=save).grid(row=0, column=1, padx=10, sticky="w")
        tk.Button(action_frame, text="Excluir", command=delete).grid(row=0, column=2, padx=10, sticky="w")

    def add_related_threat():
        def add(event=None):
            new_related_threat = related_threat_entry.get().strip()
            #Check campo vazio
            if not new_related_threat:
                messagebox.showerror("Erro", "A ameaça relacionada não pode ser vazia.")
                return
            #Check duplicidade
            if new_related_threat in related_threats_listbox.get(0, tk.END):
                messagebox.showerror("Erro", "A ameaça relacionada ja existe.")
                return
            #Adiciona na lista
            related_threats_listbox.insert(tk.END, new_related_threat)
            _threat.related_threats.append(new_related_threat)
            related_threat_window.destroy()

        #Cria a janela
        related_threat_window = tk.Toplevel(root)
        related_threat_window.geometry(f"350x100+{root.winfo_x()+100}+{root.winfo_y()+100}")
        related_threat_window.title("Incluir Ameaça Relacionada")
        #Content Frame
        content_frame = tk.Frame(related_threat_window)
        content_frame.pack(fill="both", expand=True, padx=20, pady=5)
        tk.Label(content_frame, text="Related Threat ID").pack(side="left", padx=10)
        related_threat_entry = tk.Entry(content_frame)
        related_threat_entry.insert(0, "THR-0000-0000-0000") # Exemplo
        related_threat_entry.pack(side="left", padx=10, fill="x", expand=True)
        related_threat_entry.bind("<Return>", add)
        related_threat_entry.focus_set()
        #Action Frame
        action_frame = tk.Frame(related_threat_window)
        action_frame.pack(side="bottom", padx=20, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=related_threat_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Incluir", command=add).grid(row=0, column=1, padx=10, sticky="w")
    
    def edit_related_threat():
        selected_index = related_threats_listbox.curselection()
        if not selected_index:
            return
        selected_related_threat = related_threats_listbox.get(selected_index)

        def save(event=None):
            new_related_threat = related_threat_entry.get().strip()
            #Check campo vazio
            if not new_related_threat:
                messagebox.showerror("Erro", "A ameaça relacionada não pode ser vazia.")
                return
            #Check duplicidade
            if new_related_threat in related_threats_listbox.get(0, tk.END):
                messagebox.showerror("Erro", "A ameaça relacionada ja existe.")
                return
            #Substitui na lista
            related_threats_listbox.delete(selected_index)
            related_threats_listbox.insert(selected_index, new_related_threat)
            idx_related_threat = _threat.related_threats.index(selected_related_threat)
            _threat.related_threats[idx_related_threat] = new_related_threat
            edit_window.destroy()

        def delete():
            if messagebox.askyesno("Excluir", "Deseja excluir esta ameaça relacionada?"):
                related_threats_listbox.delete(selected_index)
                edit_window.destroy()
            else:
                edit_window.lift()
        
        #Cria a janela de edição
        edit_window = tk.Toplevel(root)
        edit_window.geometry(f"350x100+{root.winfo_x()+100}+{root.winfo_y()+100}")
        edit_window.title("Editar Ameaça Relacionada")
        #Content Frame
        content_frame = tk.Frame(edit_window)
        content_frame.pack(fill="both", expand=True, padx=20, pady=5)
        tk.Label(content_frame, text="Related Threat ID").pack(side="left", padx=10)
        related_threat_entry = tk.Entry(content_frame)
        related_threat_entry.insert(0, selected_related_threat)
        related_threat_entry.pack(side="left", padx=10, fill="x", expand=True)
        related_threat_entry.focus_set()
        related_threat_entry.bind("<Return>", save)
        #Action Frame
        action_frame = tk.Frame(edit_window)
        action_frame.pack(side="bottom", padx=20, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=edit_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Salvar", command=save).grid(row=0, column=1, padx=10, sticky="ew")
        tk.Button(action_frame, text="Excluir", command=delete).grid(row=0, column=2, padx=10, sticky="w")

    def add_note():
        def add(event=None):
            new_note = note_text.get("1.0", tk.END).rstrip("\n").strip()
            #Check campo vazio
            if not new_note:
                messagebox.showerror("Erro", "A nota não pode ser vazia.")
                return
            #Check duplicidade
            if new_note in notes_listbox.get(0, tk.END):
                messagebox.showerror("Erro", "A nota ja existe.")
                return
            #Adiciona na lista
            notes_listbox.insert(tk.END, new_note)
            _threat.notes.append(new_note)
            add_window.destroy()

        #Cria uma janela para adicionar uma nova nota
        add_window = tk.Toplevel(root)
        add_window.geometry(f"400x150+{root.winfo_x()+100}+{root.winfo_y()+100}")
        add_window.title("Incluir Nota")

        content_frame = tk.Frame(add_window)
        content_frame.pack(fill="both", expand=True, padx=5, pady=5)
        tk.Label(content_frame, text="Note").pack(side="left", padx=10)
        note_text = tk.Text(content_frame, height=5)
        note_text.pack(side="left", padx=10, fill="both", expand=True)
        note_text.bind("<Control-Return>", add)
        note_text.focus_set()
        
        action_frame = tk.Frame(add_window)
        action_frame.pack(side="bottom", padx=5, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=add_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Incluir", command=add).grid(row=0, column=1, padx=10, sticky="w")
    
    def edit_note():
        #Pega a Nota selecionada
        selected_index = notes_listbox.curselection()
        if not selected_index:
            return
        selected_note = notes_listbox.get(selected_index)
        
        #Função para salvar a Nota
        def save(event=None):
            new_note = note_text.get("1.0", tk.END).rstrip("\n").strip()
            #Check campo vazio
            if not new_note:
                messagebox.showerror("Erro", "A nota não pode ser vazia.")
                return
            #Check duplicidade
            if new_note in notes_listbox.get(0, tk.END):
                messagebox.showerror("Erro", "A nota ja existe.")
                return
            #Substitui na lista
            notes_listbox.delete(selected_index)
            notes_listbox.insert(selected_index, new_note)
            idx_note = _threat.notes.index(selected_note)
            _threat.notes[idx_note] = new_note
            edit_window.destroy()
        
        #Função para excluir a Nota
        def delete():
            if messagebox.askyesno("Excluir", "Deseja excluir esta nota?"):
                notes_listbox.delete(selected_index)
                _threat.notes.remove(selected_note)
                edit_window.destroy()
            else:
                edit_window.lift()
        
        #Cria a janela de edição
        edit_window = tk.Toplevel(root)
        edit_window.geometry(f"400x150+{root.winfo_x()+100}+{root.winfo_y()+100}")
        edit_window.title("Editar Nota")

        content_frame = tk.Frame(edit_window)
        content_frame.pack(fill="both", expand=True, padx=5, pady=5)
        tk.Label(content_frame, text="Note").pack(side="left", padx=10)
        note_text = tk.Text(content_frame, height=5)
        note_text.insert("1.0", selected_note)
        note_text.pack(side="left", padx=5, fill="both", expand=True)
        note_text.bind("<Control-Return>", save)
        note_text.focus_set()
        
        action_frame = tk.Frame(edit_window)
        action_frame.pack(side="bottom", padx=20, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=edit_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Salvar", command=save).grid(row=0, column=1, padx=10, sticky="ew")
        tk.Button(action_frame, text="Excluir", command=delete).grid(row=0, column=2, padx=10, sticky="w")
    

    def save_threat_fields():
        """
        Salva os dados dos campos da Thraet no objeto _threat.
        """
        # Entradas de campos editáveis da Threat
        _threat.threat_id = threat_id_entry.get()
        _threat.title = title_entry.get().strip()
        _threat.creation_date = creation_date_entry.get()
        _threat.update_date = update_date_entry.get()
        _threat.type = type_entry.get().strip()
        _threat.domain = domain_combobox.get()
        _threat.platforms = list(platforms_listbox.get(0, tk.END))
        _threat.description = description_text.get("1.0", tk.END).strip()
        _threat.related_threats = list(related_threats_listbox.get(0, tk.END))
        _threat.notes = list(notes_listbox.get(0, tk.END))
    #########################################

    #### Widgets do threat_frame #####

    #Campos
    title_label = tk.Label(threat_frame, text="Threat Title")
    title_entry = tk.Entry(threat_frame, width=75) #O tamanho desse campo manda no tamanho da janela
    threat_id_label = tk.Label(threat_frame, text="Threat ID")
    threat_id_entry = tk.Entry(threat_frame, width=20)
    threat_id_entry.configure(state="readonly")
    creation_date_label = tk.Label(threat_frame, text="Creation Date")
    creation_date_entry = tk.Entry(threat_frame, width=30)
    creation_date_entry.configure(state="readonly")
    update_date_label = tk.Label(threat_frame, text="Update Date")
    update_date_entry = tk.Entry(threat_frame, width=30)
    update_date_entry.configure(state="readonly")
    type_label = tk.Label(threat_frame, text="Type")
    type_entry = tk.Entry(threat_frame, width=30)
    type_entry.bind("<FocusOut>", lambda event: save_threat_fields())
    domain_label = tk.Label(threat_frame, text="Domain")
    domain_var = tk.StringVar()
    domain_combobox = ttk.Combobox(threat_frame, width=30, textvariable=domain_var)
    domain_combobox['values'] = DOMAIN_LIST
    domain_combobox.bind('<<ComboboxSelected>>', lambda event: save_threat_fields())
    platforms_label = tk.Label(threat_frame, text="Platform")
    platforms_listbox = tk.Listbox(threat_frame, selectmode="single", width=30, height=3)
    platforms_listbox.bind('<<ListboxSelect>>', lambda event: edit_platform())
    platforms_listbox_scroll = tk.Scrollbar(threat_frame)
    platforms_listbox_scroll.config(command=platforms_listbox.yview)
    platforms_listbox.config(yscrollcommand=platforms_listbox_scroll.set)
    description_label = tk.Label(threat_frame, text="Description")
    description_text = tk.Text(threat_frame, width=50, height=2.5)
    description_text_scroll = tk.Scrollbar(threat_frame)
    description_text_scroll.config(command=description_text.yview)
    description_text.config(yscrollcommand=description_text_scroll.set)
    description_text.bind("<FocusOut>", lambda event: save_threat_fields())
    related_threats_label = tk.Label(threat_frame, text="Related Threats")
    related_threats_listbox = tk.Listbox(threat_frame, selectmode="single", width=50, height=3)
    related_threats_listbox.bind('<<ListboxSelect>>', lambda event: edit_related_threat())
    related_threats_listbox_scroll = tk.Scrollbar(threat_frame)
    related_threats_listbox_scroll.config(command=related_threats_listbox.yview)
    related_threats_listbox.config(yscrollcommand=related_threats_listbox_scroll.set)
    notes_label = tk.Label(threat_frame, text="Notes")
    notes_listbox = tk.Listbox(threat_frame, selectmode="single", width=50, height=3)
    notes_listbox.bind('<<ListboxSelect>>', lambda event: edit_note())
    notes_listbox_scroll = tk.Scrollbar(threat_frame)
    notes_listbox_scroll.config(command=notes_listbox.yview)
    notes_listbox.config(yscrollcommand=notes_listbox_scroll.set)
    
    #Botões
    threat_id_gen_button = tk.Button(threat_frame, text=t("<< Gerar"), command=generate_threat_id)
    platforms_add_button = tk.Button(threat_frame, text=t("Inserir >>"), command=add_platform)
    description_edit_button = tk.Button(threat_frame, text=t("Editar >>"), command=edit_description)
    related_threats_add_button = tk.Button(threat_frame, text=t("Inserir >>"), command=add_related_threat)
    notes_add_button = tk.Button(threat_frame, text=t("Inserir >>"), command=add_note)

    #Posicionamento Grid
    #Column 0
    threat_id_label.grid(row=0, column=0, padx=5, sticky="w")
    creation_date_label.grid(row=1, column=0, padx=5, sticky="w")
    update_date_label.grid(row=2, column=0, padx=5, sticky="w")
    type_label.grid(row=3, column=0, padx=5, sticky="w")
    domain_label.grid(row=4, column=0, padx=5, sticky="w")
    platforms_label.grid(row=5, column=0, padx=5, sticky="w")
    platforms_add_button.grid(row=6, column=0, padx=5, sticky="w")
    #Column 1
    threat_id_entry.grid(row=0, column=1, columnspan=2, padx=5, sticky="ew")
    creation_date_entry.grid(row=1, column=1, columnspan=3, padx=5, sticky="ew")
    update_date_entry.grid(row=2, column=1, columnspan=3, padx=5, sticky="ew")
    type_entry.grid(row=3, column=1, columnspan=3, padx=5, sticky="ew")
    domain_combobox.grid(row=4, column=1, columnspan=3, padx=5, sticky="ew")
    platforms_listbox.grid(row=5, column=1, rowspan=2, columnspan=2, padx=(5,0), sticky="ew")
    threat_frame.columnconfigure(1, weight=1)
    #Column 2
    threat_id_gen_button.grid(row=0, column=2, columnspan=2, padx=(0,5), sticky="w")
    #Column 3
    platforms_listbox_scroll.grid(row=5, column=3, rowspan=2, padx=(0,5), sticky="nsw")
    #Column 4
    title_label.grid(row=0, column=4, padx=5, sticky="w")
    description_label.grid(row=1, column=4, padx=5, sticky="w")
    description_edit_button.grid(row=2, column=4, padx=5, sticky="w")
    related_threats_label.grid(row=3, column=4, padx=5, sticky="w")
    related_threats_add_button.grid(row=4, column=4, padx=5, sticky="w")
    notes_label.grid(row=5, column=4, padx=5, sticky="w")
    notes_add_button.grid(row=6, column=4, padx=5, sticky="w")
    #Column 5
    title_entry.grid(row=0, column=5, columnspan=2, padx=5, sticky="ew")
    description_text.grid(row=1, column=5, rowspan=2, padx=(5,0), sticky="ew")
    related_threats_listbox.grid(row=3, column=5, rowspan=2, padx=(5,0), sticky="ew")
    notes_listbox.grid(row=5, column=5, rowspan=2, padx=(5,0), sticky="ew")
    threat_frame.columnconfigure(5, weight=1)
    #Column 6
    description_text_scroll.grid(row=1, column=6, rowspan=2, padx=(0,5), sticky="nsw")
    related_threats_listbox_scroll.grid(row=3, column=6, rowspan=2, padx=(0,5), sticky="nsw")
    notes_listbox_scroll.grid(row=5, column=6, rowspan=2, padx=(0,5), sticky="nsw")


    #### Funções de botão do references_frame ####

    def add_author_reference():
        #Pega id da Referência selecionada
        selected_ref_id = reference_id_entry.get()
        if selected_ref_id:
            # Pega objeto da Referência selecionada
            selected_ref = next((ref for ref in _threat.references if ref.ref_id == selected_ref_id), None)
            if not selected_ref:
                print("Erro: selected_ref == None")
                return
        else:
            #Não tem Referência selecionada
            messagebox.showerror("Erro", "Selecione uma Referência.")
            return 

        #Função do botão de adicionar novo autor
        def add(event=None):
            new_author_reference = author_reference_entry.get()
            if not new_author_reference.strip():
                messagebox.showerror("Erro", "O autor não pode ser vazio.")
                return
            # Atualiza dados da Referência selecionada no objeto _threat
            idx = _threat.references.index(selected_ref)
            _threat.references[idx].authors.append(new_author_reference.strip())
            # Atualiza listbox (se ainda selecionada a mesma referência)
            if selected_ref_id == reference_id_entry.get():
                reference_authors_listbox.insert(tk.END, new_author_reference.strip())
            add_window.destroy()

        # Cria janela para adicionar novo autor
        add_window = tk.Toplevel(root)
        add_window.geometry(f"450x100+{root.winfo_x()+100}+{root.winfo_y()+100}")
        add_window.title("Incluir Autor da Referência " + selected_ref_id)

        content_frame = tk.Frame(add_window)
        content_frame.pack(fill="both", expand=True, padx=20, pady=5)
        tk.Label(content_frame, text="Author").pack(side="left", padx=10)
        author_reference_entry = tk.Entry(content_frame)
        author_reference_entry.pack(side="left", padx=10, fill="x", expand=True)
        author_reference_entry.bind("<Return>", add)
        author_reference_entry.focus_set()
        
        action_frame = tk.Frame(add_window)
        action_frame.pack(side="bottom", padx=20, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=add_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Incluir", command=add).grid(row=0, column=1, padx=10, sticky="w")

    def edit_author_reference():
        #Pega id da Referência selecionada
        selected_ref_id = reference_id_entry.get()
        if selected_ref_id:
            # Pega objeto da Referência selecionada
            selected_ref = next((ref for ref in _threat.references if ref.ref_id == selected_ref_id), None)
            if not selected_ref:
                print("Erro: selected_ref == None")
                return
        else:
            #Não tem Referência selecionada
            messagebox.showerror("Erro", "Selecione uma Referência.")
            return 

        #Pega autor da Referência selecionada
        selected_index_listbox = reference_authors_listbox.curselection()
        if not selected_index_listbox:
            return
        selected_author_reference = reference_authors_listbox.get(selected_index_listbox)

        #Funções de botões        
        def save(event=None):
            new_author_reference = author_reference_entry.get()
            if not new_author_reference.strip():
                messagebox.showerror("Erro", "O autor não pode ser vazio.")
                return
            # Atualiza dados da Referência selecionada no objeto _threat
            idx = _threat.references.index(selected_ref)
            idx_authors = _threat.references[idx].authors.index(selected_author_reference)
            _threat.references[idx].authors[idx_authors] = new_author_reference.strip()
            # Atualiza listbox (se ainda selecionada a mesma referência)
            if selected_ref_id == reference_id_entry.get():
                reference_authors_listbox.delete(selected_index_listbox)
                reference_authors_listbox.insert(selected_index_listbox, new_author_reference.strip())
            edit_window.destroy()

        def delete():
            if messagebox.askyesno("Excluir", "Deseja excluir este autor da referência?"):
                # Atualiza dados da Referência selecionada no objeto _threat
                idx = _threat.references.index(selected_ref)
                idx_authors = _threat.references[idx].authors.index(selected_author_reference)
                _threat.references[idx].authors.pop(idx_authors)
                # Atualiza listbox (se ainda selecionada a mesma referência)
                if selected_ref_id == reference_id_entry.get():
                    reference_authors_listbox.delete(selected_index_listbox)
                edit_window.destroy()
            else:
                edit_window.lift()

        #Cria a janela de edição
        edit_window = tk.Toplevel(root)
        edit_window.geometry(f"450x100{root.winfo_x()+100}+{root.winfo_y()+100}")
        edit_window.title("Editar Autor da Referência" + selected_ref_id)

        content_frame = tk.Frame(edit_window)
        content_frame.pack(fill="both", expand=True, padx=20, pady=5)
        tk.Label(content_frame, text="Author").pack(side="left", padx=10)
        author_reference_entry = tk.Entry(content_frame)
        author_reference_entry.insert(0, selected_author_reference)
        author_reference_entry.pack(side="left", padx=10, fill="x", expand=True)
        author_reference_entry.bind("<Control-Return>", save)
        author_reference_entry.focus_set()
        
        action_frame = tk.Frame(edit_window)
        action_frame.pack(side="bottom", padx=20, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=edit_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Salvar", command=save).grid(row=0, column=1, padx=10, sticky="ew")
        tk.Button(action_frame, text="Excluir", command=delete).grid(row=0, column=2, padx=10, sticky="w")
 
    def add_note_reference():
        #Pega id da Referência selecionada
        selected_ref_id = reference_id_entry.get()
        if selected_ref_id:
            # Pega objeto da Referência selecionada
            selected_ref = next((ref for ref in _threat.references if ref.ref_id == selected_ref_id), None)
            if not selected_ref:
                print("Erro: selected_ref == None")
                return
        else:
            #Não tem Referência selecionada
            messagebox.showerror("Erro", "Selecione uma Referência.")
            return 
        
        def add(event=None):
            new_note_reference = note_reference_text.get("1.0", tk.END)
            if not new_note_reference.strip():
                messagebox.showerror("Erro", "A nota não pode ser vazia.")
                return
            # Atualiza dados da Referência selecionada no objeto _threat
            idx = _threat.references.index(selected_ref)
            _threat.references[idx].notes.append(new_note_reference.strip())
            # Atualiza listbox (se ainda selecionada a mesma referência)
            if selected_ref_id == reference_id_entry.get():
                reference_notes_listbox.insert(tk.END, new_note_reference.strip())
            add_window.destroy()

        #Cria a janela para adicionar nova nota
        add_window = tk.Toplevel(root)
        add_window.geometry(f"450x150+{root.winfo_x()+100}+{root.winfo_y()+100}")
        add_window.title("Incluir Nota da Referência" + selected_ref_id)

        content_frame = tk.Frame(add_window)
        content_frame.pack(fill="both", expand=True, padx=5, pady=5)
        tk.Label(content_frame, text="Note").pack(side="left", padx=10)
        note_reference_text = tk.Text(content_frame, height=5)
        note_reference_text.pack(side="left", padx=10, fill="both", expand=True)
        note_reference_text.bind("<Control-Return>", add)
        note_reference_text.focus_set()
        
        action_frame = tk.Frame(add_window)
        action_frame.pack(side="bottom", padx=5, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=add_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Incluir", command=add).grid(row=0, column=1, padx=10, sticky="w")

    def edit_note_reference():
        #Pega id da Referência selecionada
        selected_ref_id = reference_id_entry.get()
        if selected_ref_id:
            # Pega objeto da Referência selecionada
            selected_ref = next((ref for ref in _threat.references if ref.ref_id == selected_ref_id), None)
            if not selected_ref:
                print("Erro: selected_ref == None")
                return
        else:
            #Não tem Referência selecionada
            messagebox.showerror("Erro", "Selecione uma Referência.")
            return 

        #Pega nota da Referência selecionada
        selected_index_listbox = reference_notes_listbox.curselection()
        if not selected_index_listbox:
            return
        selected_note_reference = reference_notes_listbox.get(selected_index_listbox)
        
        #Funções de botões
        def save(event=None):
            new_note_reference = note_reference_text.get("1.0", tk.END).rstrip("\n")
            if not new_note_reference.strip():
                messagebox.showerror("Erro", "A nota não pode ser vazia.")
                return
            # Atualiza dados da Referência selecionada no objeto _threat
            idx = _threat.references.index(selected_ref)
            idx_notes = selected_index_listbox[0] # Pega o primeiro indice da tupla
            _threat.references[idx].notes[idx_notes] = new_note_reference
            # Atualiza listbox (se ainda selecionada a mesma referência)
            if selected_ref_id == reference_id_entry.get():
                reference_notes_listbox.delete(selected_index_listbox)
                reference_notes_listbox.insert(selected_index_listbox, new_note_reference)
            edit_window.destroy()

        def delete():
            if messagebox.askyesno("Excluir", "Deseja excluir esta nota da referência?"):
                # Atualiza dados da Referência selecionada no objeto _threat
                idx = _threat.references.index(selected_ref)
                idx_notes = selected_index_listbox[0] # Pega o primeiro indice da tupla
                _threat.references[idx].notes.pop(idx_notes)
                # Atualiza listbox (se ainda selecionada a mesma referência)
                if selected_ref_id == reference_id_entry.get():
                    reference_notes_listbox.delete(selected_index_listbox)
                edit_window.destroy()
            else:
                edit_window.lift()

        #Cria a janela de edição
        edit_window = tk.Toplevel(root)
        edit_window.geometry(f"400x150+{root.winfo_x()+100}+{root.winfo_y()+100}")
        edit_window.title("Editar Nota da Referência" + selected_ref_id)

        content_frame = tk.Frame(edit_window)
        content_frame.pack(fill="both", expand=True, padx=5, pady=5)
        tk.Label(content_frame, text="Note").pack(side="left", padx=10)
        note_reference_text = tk.Text(content_frame, height=5)
        note_reference_text.insert("1.0", selected_note_reference)
        note_reference_text.pack(side="left", padx=5, fill="both", expand=True)
        note_reference_text.bind("<Control-Return>", save)
        note_reference_text.focus_set()
        
        action_frame = tk.Frame(edit_window)
        action_frame.pack(side="bottom", padx=20, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=edit_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Salvar", command=save).grid(row=0, column=1, padx=10, sticky="ew")
        tk.Button(action_frame, text="Excluir", command=delete).grid(row=0, column=2, padx=10, sticky="w")


    def load_selected_reference():
        """
        Carrega nos campos correspondentes os dados da Reference selecionada na lista de referências
        """
        selection = references_listbox.curselection() # Pega item selecionado no listbox
        if selection:  # Verifica se um item está selecionado
            selected_ref_id = references_listbox.get(selection)
            selected_ref: Reference = next((ref for ref in _threat.references if ref.ref_id == selected_ref_id), None)
            if selected_ref:
                clear_reference_fields()
                reference_id_entry.configure(state="normal")
                reference_id_entry.insert(0, selected_ref.ref_id)
                reference_id_entry.configure(state="readonly")
                reference_type_entry.insert(0, selected_ref.type)
                reference_title_entry.insert(0, selected_ref.title)
                reference_link_entry.insert(0, selected_ref.link)
                reference_authors_listbox.insert(tk.END, *selected_ref.authors)
                reference_date_entry.insert(0, selected_ref.date)
                reference_notes_listbox.insert(tk.END, *selected_ref.notes)

    
    def clear_reference_fields():
        """
        Limpa os campos de dados da Referência
        """
        reference_id_entry.configure(state="normal")
        reference_id_entry.delete(0, tk.END)
        reference_id_entry.configure(state="readonly")
        reference_type_entry.delete(0, tk.END)
        reference_title_entry.delete(0, tk.END)
        reference_link_entry.delete(0, tk.END)
        reference_authors_listbox.delete(0, tk.END)
        reference_date_entry.delete(0, tk.END)
        reference_notes_listbox.delete(0, tk.END)

    
    def new_reference():
        references_listbox.selection_clear(0, tk.END)
        clear_reference_fields() #Limpa campos
        new_key = generate_key("REF") #Gera nova chave
        #Verifica se a new_key já existe na lista de Referências e incrementa a chave se existir
        while any(ref.ref_id == new_key for ref in _threat.references):
            new_key = generate_key("REF", increment=True)
        #Cria nova Referência no objeto _threat
        _threat.references.append(Reference(new_key, "", "", [], "", "", []))
        #Insere Referência na lista de Referências
        references_listbox.insert(tk.END, new_key)
        #Seleciona Referência na lista de Referências
        references_listbox.selection_set(tk.END)
        #Carrega dados da nova Referência nos campos
        load_selected_reference()
        
    def delete_reference():
        #Pega id da Referência selecionada
        selected_ref_id = reference_id_entry.get()
        if selected_ref_id:
            #Verifica se a Referência está sendo usada por alguma TTP
            ttps_with_selected_ref = [ttp for ttp in _threat.ttps if selected_ref_id in ttp.references]
            if ttps_with_selected_ref:
                messagebox.showerror("Erro", f"A Referência {selected_ref_id} não pode ser excluída porque está sendo usada por:\n{', '.join(ttp.ttp_id for ttp in ttps_with_selected_ref)}.")
                return
            #Confirma
            if messagebox.askyesno("Excluir", f"Deseja excluir a referência {selected_ref_id}?"):
                # Pega objeto da Referência selecionada
                selected_ref = next((ref for ref in _threat.references if ref.ref_id == selected_ref_id), None)
                if not selected_ref:
                    print("Erro: selected_ref == None")
                    return
                # Remove da lista de Referências em _threat
                idx = _threat.references.index(selected_ref)
                _threat.references.pop(idx)
                # Remove da listbox de Referências
                idx_listbox = references_listbox.get(0, tk.END).index(selected_ref_id)
                references_listbox.delete(idx_listbox)
                #Limpa campos
                clear_reference_fields()  
        else:
            #Não tem Referência selecionada
            messagebox.showerror("Erro", "Selecione uma Referência.")
            return
        
    
    def save_reference(verbose: bool = False):
        #Pega id da Referência selecionada
        selected_ref_id = reference_id_entry.get()
        if selected_ref_id:
            # Atualiza dados da Referência no objeto _threat
            selected_ref = next((ref for ref in _threat.references if ref.ref_id == selected_ref_id), None)
            if selected_ref:
                idx = _threat.references.index(selected_ref)
                _threat.references[idx].type = reference_type_entry.get()
                _threat.references[idx].title = reference_title_entry.get().strip('\n')
                _threat.references[idx].link = reference_link_entry.get()
                _threat.references[idx].authors = list(reference_authors_listbox.get(0, tk.END))
                _threat.references[idx].date = reference_date_entry.get()
                _threat.references[idx].notes = list(reference_notes_listbox.get(0, tk.END))
                if verbose:
                    messagebox.showinfo("Sucesso", "Dados da Referência " + selected_ref_id + " atualizados com sucesso!")
            else:
                print("Erro: selected_ref == None")
                return
        else:
            if verbose: 
                messagebox.showerror("Erro", "O ID da referência não pode ser vazio.\nCrie uma Nova Referência.")
            return


    #### Widgets do references_frame ####

    #Etrutura
    references_left_frame = tk.Frame(references_frame)
    references_left_frame.pack(side="left", anchor="nw", fill="y", expand=False, padx=5)

    references_right_frame = tk.LabelFrame(references_frame, text=t("Dados da Referência selecionada"))
    references_right_frame.pack(side="left", fill="both", expand=True, padx=5)


    ## Widgets do references_left_frame ##
    #Label título
    references_label = tk.Label(references_left_frame, text="References List")
    references_label.grid(row=0, column=0, columnspan=2, sticky="n")

    #Listbox com scrollbar  
    references_listbox = tk.Listbox(references_left_frame, selectmode="single", width=20, height=3)
    references_listbox.bind('<<ListboxSelect>>', lambda event: load_selected_reference())
    references_listbox.bind('<Down>', lambda event: mudar_selecao_listbox(references_listbox, event))
    references_listbox.bind('<Up>', lambda event: mudar_selecao_listbox(references_listbox, event))
    references_listbox.grid(row=1, column=0, sticky="nsew")

    references_listbox_vscrollbar = tk.Scrollbar(references_left_frame, orient="vertical", command=references_listbox.yview)
    references_listbox_vscrollbar.grid(row=1, column=1, sticky="ns")
    references_listbox.config(yscrollcommand=references_listbox_vscrollbar.set)
    references_left_frame.grid_rowconfigure(1, weight=1)

    #Botões
    new_reference_button = tk.Button(references_left_frame, text=t("Nova Referência"), command=new_reference)
    new_reference_button.grid(row=2, column=0, columnspan=2, pady=5, sticky="n")
 
    ## Widgets do references_right_frame ##
    #Campos
    reference_id_label = tk.Label(references_right_frame, text="ID")
    reference_id_entry = tk.Entry(references_right_frame, width=35)
    reference_id_entry.configure(state='readonly')
    reference_type_label = tk.Label(references_right_frame, text="Type")
    reference_type_entry = tk.Entry(references_right_frame, width=35)
    reference_type_entry.bind('<FocusOut>', lambda event: save_reference())
    reference_title_label = tk.Label(references_right_frame, text="Title")
    reference_title_entry = tk.Entry(references_right_frame, width=35)
    reference_title_entry.bind('<FocusOut>', lambda event: save_reference())
    reference_date_label = tk.Label(references_right_frame, text="Date")
    reference_date_entry = tk.Entry(references_right_frame, width=35)
    reference_date_entry.bind('<FocusOut>', lambda event: save_reference())
    reference_link_label = tk.Label(references_right_frame, text="Link")
    reference_link_entry = tk.Entry(references_right_frame, width=80)
    reference_link_entry.bind('<FocusOut>', lambda event: save_reference())
    reference_authors_label = tk.Label(references_right_frame, text="Authors")
    reference_authors_listbox = tk.Listbox(references_right_frame, selectmode="single", height=3, width=35)
    reference_authors_listbox.bind('<<ListboxSelect>>', lambda event: edit_author_reference())
    reference_authors_listbox_scrollbar = tk.Scrollbar(references_right_frame, orient="vertical", command=reference_authors_listbox.yview)
    reference_authors_listbox.configure(yscrollcommand=reference_authors_listbox_scrollbar.set)
    reference_notes_label = tk.Label(references_right_frame, text="Notes")
    reference_notes_listbox = tk.Listbox(references_right_frame, selectmode="single", height=3, width=35)
    reference_notes_listbox.bind('<<ListboxSelect>>', lambda event: edit_note_reference())
    reference_notes_listbox_scrollbar = tk.Scrollbar(references_right_frame, orient="vertical", command=reference_notes_listbox.yview)
    reference_notes_listbox.configure(yscrollcommand=reference_notes_listbox_scrollbar.set)

    #Botões
    reference_authors_add_button = tk.Button(references_right_frame, text=t("Inserir >>"), command=add_author_reference)
    reference_notes_add_button = tk.Button(references_right_frame, text=t("Inserir >>"), command=add_note_reference)
    #reference_save_button = tk.Button(references_right_frame, text="Salvar Referência", command=lambda: save_reference(verbose=False))
    reference_delete_button = tk.Button(references_right_frame, text=t("Excluir Referência"), command=delete_reference)

    #Organização
    #Column0
    reference_id_label.grid(row=0, column=0, padx=5, sticky="w")
    reference_type_label.grid(row=1, column=0, padx=5, sticky="w")
    reference_title_label.grid(row=2, column=0, padx=5, sticky="w")
    reference_date_label.grid(row=3, column=0, padx=5, sticky="w")
    reference_link_label.grid(row=4, column=0, padx=5, sticky="w")
    reference_delete_button.grid(row=5, column=0, columnspan=5, padx=10, pady=5) #Delete button
    #Column1
    reference_id_entry.grid(row=0, column=1, padx=5, sticky="ew")
    reference_type_entry.grid(row=1, column=1, padx=5, sticky="ew")
    reference_title_entry.grid(row=2, column=1, padx=5, sticky="ew")
    reference_date_entry.grid(row=3, column=1, padx=5, sticky="ew")
    reference_link_entry.grid(row=4, column=1, columnspan=4, padx=5, sticky="ew")
    references_right_frame.columnconfigure(1, weight=1)
    #Column2
    reference_authors_label.grid(row=0, column=2, padx=5, sticky="w")
    reference_authors_add_button.grid(row=1, column=2, padx=5, sticky="nw")
    reference_notes_label.grid(row=2, column=2, padx=5, sticky="w")
    reference_notes_add_button.grid(row=3, column=2, padx=5, sticky="nw")
    #reference_save_button.grid(row=5, column=2, columnspan=2, padx=10, pady=5, sticky="e") #Save button
    #Column3
    reference_authors_listbox.grid(row=0, column=3, rowspan=2, padx=5, sticky="ew")
    reference_notes_listbox.grid(row=2, column=3, rowspan=2, padx=5, sticky="ew")
    references_right_frame.columnconfigure(3, weight=1)
    #Column4
    reference_authors_listbox_scrollbar.grid(row=0, column=4, rowspan=2, sticky="nsw")
    reference_notes_listbox_scrollbar.grid(row=2, column=4, rowspan=2, sticky="nsw")

    #### Funções de botão do ttps_frame ####

    def select_ttp_chain():
        #Pega id da TTP selecionada
        selected_ttp_id = ttp_id_entry.get()
        if not selected_ttp_id:
            #Não tem TTP selecionada
            messagebox.showerror("Erro", "Selecione uma TTP.")
            return
        #Pega objeto da TTP selecionada
        selected_ttp = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
        if not selected_ttp:
            print("Erro: selected_ttp == None")
            return
        #Verifica se há TTPs para serem adicionadas (a prórpia TTP não vale)
        if len(_threat.ttps) == 1 and _threat.ttps[0].ttp_id == selected_ttp_id:
            messagebox.showerror("Erro", "Não há outras TTPs para adicionar.")
            return
         
        def on_select_ttp_id(event=None):
            print_selected_ttp_listbox(ttp_ids_listbox, _threat, selected_new_ttp_text, attck_src)
        
        def add(event=None):
            selected_new_ttp_id = ttp_ids_listbox.get(ttp_ids_listbox.curselection()) if ttp_ids_listbox.curselection() else None
            if selected_new_ttp_id:
                if selected_new_ttp_id == selected_ttp.ttp_id:
                    messagebox.showerror("Erro", "Não pode incluir o própria TTP na Chain.")
                    select_window.lift()
                    return
                #Verifica se já existe, para não incluir duplicata
                if selected_new_ttp_id in selected_ttp.ttp_chain:
                    messagebox.showerror("Erro", "Esta TTP já existe na TTP Chain.")
                    select_window.lift()
                    return
                # Atualiza o objeto _threat
                idx = _threat.ttps.index(selected_ttp)
                _threat.ttps[idx].ttp_chain.append(selected_new_ttp_id)
                # Atualiza listbox (se ainda selecionada a mesma ttp)
                if selected_ttp_id == ttp_id_entry.get():
                    ttp_chain_listbox.insert(tk.END, selected_new_ttp_id)
                select_window.destroy()
                
        #Cria janela
        select_window = tk.Toplevel(root)
        select_window.title("Incluir TTP na TTP Chain de " + selected_ttp_id)
        select_window.geometry(f"500x300+{root.winfo_x()+100}+{root.winfo_y()+100}")
        #Content Frame
        content_frame = tk.Frame(select_window)
        content_frame.pack(fill="both", expand=True, padx=5, pady=5)
        #Column0
        tk.Label(content_frame, text="TTPs").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        ttp_ids_listbox = tk.Listbox(content_frame, width=25, height=5, selectmode="single")
        ttp_ids_listbox.grid(row=1, column=0, padx=5, sticky="wns")
        ttp_ids_listbox.bind("<<ListboxSelect>>", on_select_ttp_id)
        #Povoa listbox
        for ttp in _threat.ttps:
            if ttp.ttp_id == selected_ttp_id:
                continue #Evita inclusão da prória ttp na listbox
            ttp_ids_listbox.insert(tk.END, ttp.ttp_id)
        ttp_ids_listbox.focus_set()
        ttp_ids_listbox.bind("<Return>", add)
        #Column1
        tk.Label(content_frame, text="Dados da TTP").grid(row=0, column=1, padx=5, pady=5, sticky="w")
        selected_new_ttp_text = tk.Text(content_frame, width=40, height=5, state="disabled")
        selected_new_ttp_text.grid(row=1, column=1, padx=(5,0), pady=5, sticky="news")
        content_frame.columnconfigure(1, weight=1)
        #Column2
        vscrollbar = tk.Scrollbar(content_frame, orient="vertical", command=selected_new_ttp_text.yview)
        vscrollbar.grid(row=1, column=2, padx=(0,5), sticky="ns")
        selected_new_ttp_text.configure(yscrollcommand=vscrollbar.set)

        content_frame.rowconfigure(1, weight=1)
        #Action Frame
        action_frame = tk.Frame(select_window)
        action_frame.pack(side="bottom", padx=20, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=select_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Incluir", command=add).grid(row=0, column=1, padx=10, sticky="w")
        #Seleciona primeiro item da listbox
        if ttp_ids_listbox.size() > 0:
            ttp_ids_listbox.select_set(0) 
            on_select_ttp_id()

    def edit_exclude_ttp_chain():
        #Pega id da TTP selecionada
        selected_ttp_id = ttp_id_entry.get()
        if not selected_ttp_id:
            #Não tem TTP selecionada
            messagebox.showerror("Erro", "Selecione uma TTP.")
            return
        #Pega objeto da TTP selecionada
        selected_ttp = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
        if not selected_ttp:
            print("Erro: selected_ttp == None")
            return
        
        #Pega ttp_chain selecionada da TTP selecionada
        selected_index_listbox = ttp_chain_listbox.curselection()
        if not selected_index_listbox:
            return
        initial_ttp_chain = ttp_chain_listbox.get(selected_index_listbox)
        
        def on_select_ttp_id(event=None):
            print_selected_ttp_listbox(ttp_ids_listbox, _threat, selected_new_ttp_text, attck_src)
        
        def save(event=None):
            selected_new_ttp_id = ttp_ids_listbox.get(ttp_ids_listbox.curselection()) if ttp_ids_listbox.curselection() else None
            if selected_new_ttp_id:
                if selected_new_ttp_id == initial_ttp_chain: #É a mesma ttp, logo não precisa atualizar
                    select_window.destroy()
                    return
                #Verifica se já existe, para não incluir duplicata
                if selected_new_ttp_id in selected_ttp.ttp_chain:
                    messagebox.showerror("Erro", "Esta TTP já existe na TTP Chain.")
                    select_window.lift()
                    return
                # Atualiza dados da TTP selecionada no objeto _threat
                idx = _threat.ttps.index(selected_ttp)
                #idx_ttp_chain = selected_index_listbox[0] # Pega o primeiro indice da tupla
                idx_ttp_chain = _threat.ttps[idx].ttp_chain.index(initial_ttp_chain)
                _threat.ttps[idx].ttp_chain[idx_ttp_chain] = selected_new_ttp_id
                # Atualiza listbox (se ainda selecionada a mesma ttp)
                if selected_ttp_id == ttp_id_entry.get():
                    ttp_chain_listbox.delete(selected_index_listbox)
                    ttp_chain_listbox.insert(selected_index_listbox, selected_new_ttp_id)
                select_window.destroy()

        def delete():
            if messagebox.askyesno("Excluir", "Deseja excluir a " + initial_ttp_chain + " da TTP Chain?"):
                # Atualiza dados da TTP selecionada no objeto _threat
                idx = _threat.ttps.index(selected_ttp)
                _threat.ttps[idx].ttp_chain.remove(initial_ttp_chain)
                # Atualiza listbox (se ainda selecionada a mesma ttp)
                if selected_ttp_id == ttp_id_entry.get():
                    ttp_chain_listbox.delete(selected_index_listbox)
                select_window.destroy()

        #Cria janela
        select_window = tk.Toplevel()
        select_window.title("Alterar/Excluir TTP da TTP Chain de " + selected_ttp_id)
        select_window.geometry(f"500x300+{root.winfo_x()+100}+{root.winfo_y()+100}")
        #Content Frame
        content_frame = tk.Frame(select_window)
        content_frame.pack(fill="both", expand=True, padx=5, pady=5)
        #Column0
        tk.Label(content_frame, text="TTP ID da Chain selecionada:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        tk.Label(content_frame, text="TTPs").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        ttp_ids_listbox = tk.Listbox(content_frame, width=25, height=5, selectmode="single")
        ttp_ids_listbox.grid(row=2, column=0, padx=5, sticky="wns")
        ttp_ids_listbox.bind("<<ListboxSelect>>", on_select_ttp_id)
        #Povoa listbox
        for ttp in _threat.ttps:
            if ttp.ttp_id == selected_ttp_id:
                continue #Evita inclusão da prória ttp na listbox
            ttp_ids_listbox.insert(tk.END, ttp.ttp_id)
        ttp_ids_listbox.focus_set()
        ttp_ids_listbox.bind("<Return>", save)
        #Column1
        initial_ttp_chain_id_entry = tk.Entry(content_frame, width=22)
        initial_ttp_chain_id_entry.insert(0, initial_ttp_chain)
        initial_ttp_chain_id_entry.configure(state="readonly")
        initial_ttp_chain_id_entry.grid(row=0, column=1, columnspan=2, padx=5, pady=5, sticky="w")
        tk.Label(content_frame, text="Dados da TTP").grid(row=1, column=1, padx=5, pady=5, sticky="w")
        selected_new_ttp_text = tk.Text(content_frame, width=40, height=5, state="disabled")
        selected_new_ttp_text.grid(row=2, column=1, columnspan=2, padx=(5,0), pady=5, sticky="news")
        content_frame.columnconfigure(1, weight=1)
        #Column2
        tk.Button(content_frame, text="Excluir", command=delete).grid(row=0, column=2, padx=5, sticky="w")
        #Column3
        vscrollbar = tk.Scrollbar(content_frame, orient="vertical", command=selected_new_ttp_text.yview)
        vscrollbar.grid(row=2, column=3, padx=(0,5), sticky="ns")
        selected_new_ttp_text.configure(yscrollcommand=vscrollbar.set)

        content_frame.rowconfigure(2, weight=1)
        #Action Frame
        action_frame = tk.Frame(select_window)
        action_frame.pack(side="bottom", padx=20, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=select_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Salvar", command=save).grid(row=0, column=1, padx=10, sticky="w")
        #Seleciona na listbox o mesmo id que foi selecionado no listbox do app
        for i, ref_id in enumerate(ttp_ids_listbox.get(0, tk.END)):
            if ref_id == initial_ttp_chain:
                ttp_ids_listbox.select_set(i)
                on_select_ttp_id()
                break


    def select_related_ttp():
        #Pega id da TTP selecionada
        selected_ttp_id = ttp_id_entry.get()
        if not selected_ttp_id:
            #Não tem TTP selecionada
            messagebox.showerror("Erro", "Selecione uma TTP.")
            return
        #Pega objeto da TTP selecionada
        selected_ttp = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
        if not selected_ttp:
            print("Erro: selected_ttp == None")
            return
        #Verifica se há TTPs para serem adicionadas (a prórpia TTP não vale)
        if len(_threat.ttps) == 1 and _threat.ttps[0].ttp_id == selected_ttp_id:
            messagebox.showerror("Erro", "Não há outras TTPs para adicionar.")
            return
         
        def on_select_ttp_id(event=None):
            print_selected_ttp_listbox(ttp_ids_listbox, _threat, selected_new_ttp_text, attck_src)
        
        def add(event=None):
            selected_new_ttp_id = ttp_ids_listbox.get(ttp_ids_listbox.curselection()) if ttp_ids_listbox.curselection() else None
            if selected_new_ttp_id:
                if selected_new_ttp_id == selected_ttp.ttp_id:
                    messagebox.showerror("Erro", "Não pode incluir o própria TTP como relacionada.")
                    select_window.lift()
                    return
                #Verifica se já existe, para não incluir duplicata
                if selected_new_ttp_id in selected_ttp.related_ttps:
                    messagebox.showerror("Erro", "Esta TTP já existe como TTP relacionada.")
                    select_window.lift()
                    return
                # Atualiza o objeto _threat
                idx = _threat.ttps.index(selected_ttp)
                _threat.ttps[idx].related_ttps.append(selected_new_ttp_id)
                # Atualiza listbox (se ainda selecionada a mesma ttp)
                if selected_ttp_id == ttp_id_entry.get():
                    ttp_related_ttps_listbox.insert(tk.END, selected_new_ttp_id)
                select_window.destroy()
                
        #Cria janela
        select_window = tk.Toplevel(root)
        select_window.title("Incluir TTP como TTP relacionada de " + selected_ttp_id)
        select_window.geometry(f"500x300+{root.winfo_x()+100}+{root.winfo_y()+100}")
        #Content Frame
        content_frame = tk.Frame(select_window)
        content_frame.pack(fill="both", expand=True, padx=5, pady=5)
        #Column0
        tk.Label(content_frame, text="TTPs").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        ttp_ids_listbox = tk.Listbox(content_frame, width=25, height=5, selectmode="single")
        ttp_ids_listbox.grid(row=1, column=0, padx=5, sticky="wns")
        ttp_ids_listbox.bind("<<ListboxSelect>>", on_select_ttp_id)
        #Povoa listbox
        for ttp in _threat.ttps:
            if ttp.ttp_id == selected_ttp_id:
                continue #Evita inclusão da prória ttp na listbox
            ttp_ids_listbox.insert(tk.END, ttp.ttp_id)
        ttp_ids_listbox.focus_set()
        ttp_ids_listbox.bind("<Return>", add)
        #Column1
        tk.Label(content_frame, text="Dados da TTP").grid(row=0, column=1, padx=5, pady=5, sticky="w")
        selected_new_ttp_text = tk.Text(content_frame, width=40, height=5, state="disabled")
        selected_new_ttp_text.grid(row=1, column=1, padx=(5,0), pady=5, sticky="news")
        content_frame.columnconfigure(1, weight=1)
        #Column2
        vscrollbar = tk.Scrollbar(content_frame, orient="vertical", command=selected_new_ttp_text.yview)
        vscrollbar.grid(row=1, column=2, padx=(0,5), sticky="ns")
        selected_new_ttp_text.configure(yscrollcommand=vscrollbar.set)
        content_frame.rowconfigure(1, weight=1)
        #Action Frame
        action_frame = tk.Frame(select_window)
        action_frame.pack(side="bottom", padx=20, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=select_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Incluir", command=add).grid(row=0, column=1, padx=10, sticky="w")
        #Seleciona primeiro item da listbox
        if ttp_ids_listbox.size() > 0:
            ttp_ids_listbox.select_set(0) 
            on_select_ttp_id()

    def edit_exclude_related_ttp():
        #Pega id da TTP selecionada
        selected_ttp_id = ttp_id_entry.get()
        if not selected_ttp_id:
            #Não tem TTP selecionada
            messagebox.showerror("Erro", "Selecione uma TTP.")
            return
        #Pega objeto da TTP selecionada
        selected_ttp = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
        if not selected_ttp:
            print("Erro: selected_ttp == None")
            return
        
        #Pega related_ttps selecionada da TTP selecionada
        selected_index_listbox = ttp_related_ttps_listbox.curselection()
        if not selected_index_listbox:
            return
        initial_related_ttps = ttp_related_ttps_listbox.get(selected_index_listbox)
        
        def on_select_ttp_id(event=None):
            print_selected_ttp_listbox(ttp_ids_listbox, _threat, selected_new_ttp_text, attck_src)
        
        def save(event=None):
            selected_new_ttp_id = ttp_ids_listbox.get(ttp_ids_listbox.curselection()) if ttp_ids_listbox.curselection() else None
            if selected_new_ttp_id:
                if selected_new_ttp_id == initial_related_ttps: #É a mesma ttp, logo não precisa atualizar
                    select_window.destroy()
                    return
                #Verifica se já existe, para não incluir duplicata
                if selected_new_ttp_id in selected_ttp.related_ttps:
                    messagebox.showerror("Erro", "Esta TTP já existe como TTP relacionada.")
                    select_window.lift()
                    return
                # Atualiza dados da TTP selecionada no objeto _threat
                idx = _threat.ttps.index(selected_ttp)
                idx_related_ttps = _threat.ttps[idx].related_ttps.index(initial_related_ttps)
                _threat.ttps[idx].related_ttps[idx_related_ttps] = selected_new_ttp_id
                # Atualiza listbox (se ainda selecionada a mesma ttp)
                if selected_ttp_id == ttp_id_entry.get():
                    ttp_related_ttps_listbox.delete(selected_index_listbox)
                    ttp_related_ttps_listbox.insert(selected_index_listbox, selected_new_ttp_id)
                select_window.destroy()

        def delete():
            if messagebox.askyesno("Excluir", "Deseja excluir a " + initial_related_ttps + " das TTPs relacionadas?"):
                # Atualiza dados da TTP selecionada no objeto _threat
                idx = _threat.ttps.index(selected_ttp)
                _threat.ttps[idx].related_ttps.remove(initial_related_ttps)
                # Atualiza listbox (se ainda selecionada a mesma ttp)
                if selected_ttp_id == ttp_id_entry.get():
                    ttp_related_ttps_listbox.delete(selected_index_listbox)
                select_window.destroy()

        #Cria janela
        select_window = tk.Toplevel()
        select_window.title("Alterar/Excluir TTP da TTPs relacionadas de " + selected_ttp_id)
        select_window.geometry(f"500x300+{root.winfo_x()+100}+{root.winfo_y()+100}")
        #Content Frame
        content_frame = tk.Frame(select_window)
        content_frame.pack(fill="both", expand=True, padx=5, pady=5)
        #Column0
        tk.Label(content_frame, text="ID da Related TTP selecionada:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        tk.Label(content_frame, text="TTPs").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        ttp_ids_listbox = tk.Listbox(content_frame, width=25, height=5, selectmode="single")
        ttp_ids_listbox.grid(row=2, column=0, padx=5, sticky="wns")
        ttp_ids_listbox.bind("<<ListboxSelect>>", on_select_ttp_id)
        #Povoa listbox
        for ttp in _threat.ttps:
            if ttp.ttp_id == selected_ttp_id:
                continue #Evita inclusão da prória ttp na listbox
            ttp_ids_listbox.insert(tk.END, ttp.ttp_id)
        ttp_ids_listbox.focus_set()
        ttp_ids_listbox.bind("<Return>", save)
        #Column1
        initial_related_ttps_id_entry = tk.Entry(content_frame, width=22)
        initial_related_ttps_id_entry.insert(0, initial_related_ttps)
        initial_related_ttps_id_entry.configure(state="readonly")
        initial_related_ttps_id_entry.grid(row=0, column=1, columnspan=2, padx=5, pady=5, sticky="w")
        tk.Label(content_frame, text="Dados da TTP").grid(row=1, column=1, padx=5, pady=5, sticky="w")
        selected_new_ttp_text = tk.Text(content_frame, width=40, height=5, state="disabled")
        selected_new_ttp_text.grid(row=2, column=1, columnspan=2, padx=(5,0), pady=5, sticky="news")
        content_frame.columnconfigure(1, weight=1)
        #Column2
        tk.Button(content_frame, text="Excluir", command=delete).grid(row=0, column=2, padx=5, sticky="w")
        #Column3
        vscrollbar = tk.Scrollbar(content_frame, orient="vertical", command=selected_new_ttp_text.yview)
        vscrollbar.grid(row=2, column=3, padx=(0,5), sticky="ns")
        selected_new_ttp_text.configure(yscrollcommand=vscrollbar.set)

        content_frame.rowconfigure(2, weight=1)
        #Action Frame
        action_frame = tk.Frame(select_window)
        action_frame.pack(side="bottom", padx=20, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=select_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Salvar", command=save).grid(row=0, column=1, padx=10, sticky="w")
        #Seleciona na listbox o mesmo id que foi selecionado no listbox do app
        for i, ref_id in enumerate(ttp_ids_listbox.get(0, tk.END)):
            if ref_id == initial_related_ttps:
                ttp_ids_listbox.select_set(i)
                on_select_ttp_id()
                break

    
    def select_ttp_reference():
        #Pega id da TTP selecionada
        selected_ttp_id = ttp_id_entry.get()
        if not selected_ttp_id:
            #Não tem TTP selecionada
            messagebox.showerror("Erro", "Selecione uma TTP.")
            return
        #Pega objeto da TTP selecionada
        selected_ttp = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
        if not selected_ttp:
            print("Erro: selected_ttp == None")
            return
        #Verifica se há referencias para serem adicionadas
        if not _threat.references:
            messagebox.showerror("Erro", "Não há referências para adicionar.")
            return
        
        def on_select_ref_id(event=None):
            print_selected_ref_listbox(ref_ids_listbox, _threat, selected_ref_text)
        
        def add(event=None):
            selected_ref_id = ref_ids_listbox.get(ref_ids_listbox.curselection()) if ref_ids_listbox.curselection() else None
            if selected_ref_id:
                #Verifica se já existe, para não incluir duplicata
                if selected_ref_id in selected_ttp.references:
                    messagebox.showerror("Erro", "Esta referência já existe na TTP.")
                    select_window.lift()
                    return
                # Atualiza o objeto _threat
                idx = _threat.ttps.index(selected_ttp)
                _threat.ttps[idx].references.append(selected_ref_id)
                # Atualiza listbox (se ainda selecionada a mesma ttp)
                if selected_ttp_id == ttp_id_entry.get():
                    ttp_references_listbox.insert(tk.END, selected_ref_id)
                select_window.destroy()
            else:
                messagebox.showerror("Erro", "Selecione uma Referência.")
                select_window.lift()

        #Cria janela
        select_window = tk.Toplevel(root)
        select_window.title("Selecionar Referência para a " + selected_ttp_id)
        select_window.geometry(f"500x300+{root.winfo_x()+100}+{root.winfo_y()+100}")
        #Content Frame
        content_frame = tk.Frame(select_window)
        content_frame.pack(fill="both", expand=True, padx=5, pady=5)
        #Column0
        tk.Label(content_frame, text="Referências").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        ref_ids_listbox = tk.Listbox(content_frame, width=25, height=5, selectmode="single")
        ref_ids_listbox.grid(row=1, column=0, padx=5, sticky="wns")
        ref_ids_listbox.bind("<<ListboxSelect>>", on_select_ref_id)
        #Povoa listbox
        for ref in _threat.references:
            ref_ids_listbox.insert(tk.END, ref.ref_id)
        ref_ids_listbox.focus_set()
        ref_ids_listbox.bind("<Return>", add)
        #Column1
        tk.Label(content_frame, text="Dados da Referência").grid(row=0, column=1, padx=5, pady=5, sticky="w")
        selected_ref_text = tk.Text(content_frame, width=40, height=5, state="disabled")
        selected_ref_text.grid(row=1, column=1, padx=(5,0), pady=5, sticky="news")
        content_frame.columnconfigure(1, weight=1)
        #Column2
        vscrollbar = tk.Scrollbar(content_frame, orient="vertical", command=selected_ref_text.yview)
        vscrollbar.grid(row=1, column=2, padx=(0,5), sticky="ns")
        selected_ref_text.configure(yscrollcommand=vscrollbar.set)

        content_frame.rowconfigure(1, weight=1)
        #Action Frame
        action_frame = tk.Frame(select_window)
        action_frame.pack(side="bottom", padx=20, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=select_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Incluir", command=add).grid(row=0, column=1, padx=10, sticky="w")
        #Seleciona primeiro item da listbox
        if ref_ids_listbox.size() > 0:
            ref_ids_listbox.select_set(0) 
            on_select_ref_id()

    def edit_exclude_ttp_reference():
        #Pega id da TTP selecionada
        selected_ttp_id = ttp_id_entry.get()
        if not selected_ttp_id:
            #Não tem TTP selecionada
            messagebox.showerror("Erro", "Selecione uma TTP.")
            return
        #Pega objeto da TTP selecionada
        selected_ttp = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
        if not selected_ttp:
            print("Erro: selected_ttp == None")
            return
        
        #Pega referência da TTP selecionada
        selected_index_listbox = ttp_references_listbox.curselection()
        if not selected_index_listbox:
            return
        initial_ref_ttp = ttp_references_listbox.get(selected_index_listbox)
        
        def on_select_ref_id(event=None):
            print_selected_ref_listbox(ref_ids_listbox, _threat, selected_ref_text)
        
        def save(event=None):
            selected_ref_id = ref_ids_listbox.get(ref_ids_listbox.curselection()) if ref_ids_listbox.curselection() else None
            if selected_ref_id:
                if selected_ref_id == initial_ref_ttp: #É a mesma referencia, logo não precisa atualizar
                    select_window.destroy()
                    return
                # Atualiza dados da TTP selecionada no objeto _threat
                idx = _threat.ttps.index(selected_ttp)
                idx_ref = selected_index_listbox[0] # Pega o primeiro indice da tupla
                _threat.ttps[idx].references[idx_ref] = selected_ref_id
                # Atualiza listbox (se ainda selecionada a mesma ttp)
                if selected_ttp_id == ttp_id_entry.get():
                    ttp_references_listbox.delete(selected_index_listbox)
                    ttp_references_listbox.insert(selected_index_listbox, selected_ref_id)
                select_window.destroy()
            else:
                messagebox.showerror("Erro", "Selecione uma Referência.")
                select_window.lift()

        def delete():
            if messagebox.askyesno("Excluir", "Deseja excluir a referêrncia " + initial_ref_ttp + " da TTP?"):
                # Atualiza dados da TTP selecionada no objeto _threat
                idx = _threat.ttps.index(selected_ttp)
                idx_ref = selected_index_listbox[0] # Pega o primeiro indice da tupla
                _threat.ttps[idx].references.pop(idx_ref)
                # Atualiza listbox (se ainda selecionada a mesma ttp)
                if selected_ttp_id == ttp_id_entry.get():
                    ttp_references_listbox.delete(selected_index_listbox)
                select_window.destroy()
            else:
                select_window.lift()

        #Cria janela
        select_window = tk.Toplevel(root)
        select_window.title("Selecionar Referência para a " + selected_ttp_id)
        select_window.geometry(f"500x300+{root.winfo_x()+100}+{root.winfo_y()+100}")
        #Content Frame
        content_frame = tk.Frame(select_window)
        content_frame.pack(fill="both", expand=True, padx=5, pady=5)
        #Column0
        tk.Label(content_frame, text="Ref. ID selecionada:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        tk.Label(content_frame, text="Referências").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        ref_ids_listbox = tk.Listbox(content_frame, width=25, height=5, selectmode="single")
        ref_ids_listbox.grid(row=2, column=0, padx=5, sticky="wns")
        ref_ids_listbox.bind("<<ListboxSelect>>", on_select_ref_id)
        #Povoa listbox
        for ref in _threat.references:
            ref_ids_listbox.insert(tk.END, ref.ref_id)
        ref_ids_listbox.focus_set()
        ref_ids_listbox.bind("<Return>", save)
        #Column1
        initial_ref_id_entry = tk.Entry(content_frame, width=25)
        initial_ref_id_entry.insert(0, initial_ref_ttp)
        initial_ref_id_entry.configure(state="readonly")
        initial_ref_id_entry.grid(row=0, column=1, columnspan=2, padx=5, pady=5, sticky="w")
        tk.Label(content_frame, text="Dados da Referência").grid(row=1, column=1, padx=5, pady=5, sticky="w")
        selected_ref_text = tk.Text(content_frame, width=40, height=5, state="disabled")
        selected_ref_text.grid(row=2, column=1, columnspan=2, padx=(5,0), sticky="news")
        content_frame.columnconfigure(1, weight=1)
        #Column2
        tk.Button(content_frame, text="Excluir", command=delete).grid(row=0, column=2, padx=5, sticky="w")
        #Column3
        vscrollbar = tk.Scrollbar(content_frame, orient="vertical", command=selected_ref_text.yview)
        vscrollbar.grid(row=2, column=3, padx=(0,5), sticky="ns")
        selected_ref_text.configure(yscrollcommand=vscrollbar.set)
        
        content_frame.rowconfigure(2, weight=1)
        #Action Frame
        action_frame = tk.Frame(select_window)
        action_frame.pack(side="bottom", padx=20, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=select_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Salvar", command=save).grid(row=0, column=1, padx=10, sticky="w")
        #Seleciona na listbox o mesmo id que foi selecionado no listbox do app
        for i, ref_id in enumerate(ref_ids_listbox.get(0, tk.END)):
            if ref_id == initial_ref_ttp:
                ref_ids_listbox.select_set(i)
                on_select_ref_id()
                break

    def add_ttp_note():
        #Pega id da TTP selecionada
        selected_ttp_id = ttp_id_entry.get()
        if selected_ttp_id:
            # Pega objeto da TTP selecionada
            selected_ttp = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
            if not selected_ttp:
                print("Erro: selected_ttp == None")
                return
        else:
            #Não tem TTP selecionada
            messagebox.showerror("Erro", "Selecione uma TTP.")
            return 
        #Função para adicionar nova Nota
        def add(event=None):
            new_ttp_note = ttp_note_text.get("1.0", tk.END).rstrip("\n").strip()
            if not new_ttp_note:
                messagebox.showerror("Erro", "A nota não pode ser vazia.")
                return
            # Atualiza dados da TTP selecionada no objeto _threat
            idx = _threat.ttps.index(selected_ttp)
            _threat.ttps[idx].notes.append(new_ttp_note)
            # Atualiza listbox (se ainda selecionada a mesma ttp)
            if selected_ttp_id == ttp_id_entry.get():
                ttp_notes_listbox.insert(tk.END, new_ttp_note)
            add_window.destroy()
        #Cria janela para adicionar nova ttp_chain
        add_window = tk.Toplevel(root)
        add_window.geometry(f"450x150+{root.winfo_x()+100}+{root.winfo_y()+100}")
        add_window.title("Incluir Nota na TTP" + selected_ttp_id)

        content_frame = tk.Frame(add_window)
        content_frame.pack(fill="both", expand=True, padx=5, pady=5)
        tk.Label(content_frame, text="Nota").pack(side="left", padx=10)
        ttp_note_text = tk.Text(content_frame, height=5)
        ttp_note_text.pack(side="left", padx=10, fill="both", expand=True)
        ttp_note_text.bind("<Control-Return>", add)
        ttp_note_text.focus_set()
        
        action_frame = tk.Frame(add_window)
        action_frame.pack(side="bottom", padx=5, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=add_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Incluir", command=add).grid(row=0, column=1, padx=10, sticky="w")

    def edit_ttp_note():
        #Pega id da TTP selecionada
        selected_ttp_id = ttp_id_entry.get()
        if selected_ttp_id:
            # Pega objeto da TTP selecionada
            selected_ttp = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
            if not selected_ttp:
                print("Erro: selected_ttp == None")
                return
        else:
            #Não tem TTP selecionada
            messagebox.showerror("Erro", "Selecione uma TTP.")
            return 

        #Pega nota da TTP selecionada
        selected_index_listbox = ttp_notes_listbox.curselection()
        if not selected_index_listbox:
            return
        selected_note_ttp = ttp_notes_listbox.get(selected_index_listbox)
        
        #Funções de botões
        def save(event=None):
            new_note_ttp = note_ttp_text.get("1.0", tk.END).rstrip("\n").strip()
            if not new_note_ttp:
                messagebox.showerror("Erro", "A nota não pode ser vazia.")
                return
            # Atualiza dados da TTP selecionada no objeto _threat
            idx = _threat.ttps.index(selected_ttp)
            idx_notes = _threat.ttps[idx].notes.index(selected_note_ttp)
            _threat.ttps[idx].notes[idx_notes] = new_note_ttp
            # Atualiza listbox (se ainda selecionada a mesma ttp)
            if selected_ttp_id == ttp_id_entry.get():
                ttp_notes_listbox.delete(selected_index_listbox)
                ttp_notes_listbox.insert(selected_index_listbox, new_note_ttp)
            edit_window.destroy()

        def delete():
            if messagebox.askyesno("Excluir", "Deseja excluir esta nota da TTP?"):
                # Atualiza dados da TTP selecionada no objeto _threat
                idx = _threat.ttps.index(selected_ttp)
                _threat.ttps[idx].notes.remove(selected_note_ttp)
                # Atualiza listbox (se ainda selecionada a mesma ttp)
                if selected_ttp_id == ttp_id_entry.get():
                    ttp_notes_listbox.delete(selected_index_listbox)
                edit_window.destroy()
            else:
                edit_window.lift()

        #Cria a janela de edição
        edit_window = tk.Toplevel(root)
        edit_window.geometry(f"400x150+{root.winfo_x()+100}+{root.winfo_y()+100}")
        edit_window.title("Editar Nota da TTP" + selected_ttp_id)

        content_frame = tk.Frame(edit_window)
        content_frame.pack(fill="both", expand=True, padx=5, pady=5)
        tk.Label(content_frame, text="Nota").pack(side="left", padx=10)
        note_ttp_text = tk.Text(content_frame, height=5)
        note_ttp_text.pack(side="left", padx=10, fill="both", expand=True)
        note_ttp_text.insert(tk.END, selected_note_ttp)
        note_ttp_text.bind("<Control-Return>", save)
        note_ttp_text.focus_set()
        
        action_frame = tk.Frame(edit_window)
        action_frame.pack(side="bottom", padx=20, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=edit_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Salvar", command=save).grid(row=0, column=1, padx=10, sticky="w")
        tk.Button(action_frame, text="Excluir", command=delete).grid(row=0, column=2, padx=10, sticky="w")

    def add_ttp_secondary_technique():
        #Pega id da TTP selecionada
        selected_ttp_id = ttp_id_entry.get()
        if selected_ttp_id:
            # Pega objeto da TTP selecionada
            selected_ttp = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
            if not selected_ttp:
                print("Erro: selected_ttp == None")
                return
        else:
            #Não tem TTP selecionada
            messagebox.showerror("Erro", "Selecione uma TTP.")
            return 

        def add(event=None):
            new_ttp_secondary_technique = ttp_secondary_technique_entry.get().strip()
            #Check vazio
            if not new_ttp_secondary_technique:
                messagebox.showerror("Erro", "Não pode inserir um valor vazio.")
                return
            #Check duplicidade
            if new_ttp_secondary_technique in selected_ttp.secondary_techniques:
                messagebox.showerror("Erro", "Esta Técnica Secundária já existe.")
                return
            # Atualiza dados da TTP selecionada no objeto _threat
            idx = _threat.ttps.index(selected_ttp)
            _threat.ttps[idx].secondary_techniques.append(new_ttp_secondary_technique)
            # Atualiza listbox (se ainda selecionada a mesma ttp)
            if selected_ttp_id == ttp_id_entry.get():
                ttp_secondary_techniques_listbox.insert(tk.END, new_ttp_secondary_technique)
            add_window.destroy()
        
        def consulta_nome_ttp(event=None):
            entrada = ttp_secondary_technique_entry.get()
            ttp_secondary_technique_name_entry.configure(state="normal")
            if re.match(r"T\d{4}(\.\d{3})?", entrada):
                nome = get_technique_name(attck_src, entrada)
                if nome:
                    ttp_secondary_technique_name_entry.delete(0, tk.END)
                    ttp_secondary_technique_name_entry.insert(0, nome)
                else:
                    ttp_secondary_technique_name_entry.delete(0, tk.END)
                    ttp_secondary_technique_name_entry.insert(0, "<<Nome não encontrado>>")
            else:
                ttp_secondary_technique_name_entry.delete(0, tk.END)
            ttp_secondary_technique_name_entry.configure(state="readonly")

        #Cria janela
        add_window = tk.Toplevel(root)
        add_window.geometry(f"500x120+{root.winfo_x()+100}+{root.winfo_y()+100}")
        add_window.title("Incluir (Sub)Técnica Secundária da " + selected_ttp_id)
        #Content Frame
        content_frame = tk.Frame(add_window)
        content_frame.pack(fill="both", expand=True, padx=10, pady=5)
        #Column0
        tk.Label(content_frame, text="(Sub)Técnica Secundária").grid(row=0, column=0, padx=(0,10), pady=10, sticky="w")
        #tk.Label(content_frame, text="Nome").grid(row=1, column=0, padx=10, sticky="w")
        #Column1
        ttp_secondary_technique_entry = tk.Entry(content_frame, width=35)
        ttp_secondary_technique_entry.insert(0, "T0000.000") #Exemplo
        ttp_secondary_technique_entry.grid(row=0, column=1, sticky="ew")
        ttp_secondary_technique_entry.bind("<Return>", add)
        ttp_secondary_technique_entry.bind("<KeyRelease>", consulta_nome_ttp)
        ttp_secondary_technique_entry.focus_set()
        ttp_secondary_technique_name_entry = tk.Entry(content_frame, width=35)
        ttp_secondary_technique_name_entry.configure(state="readonly")
        ttp_secondary_technique_name_entry.grid(row=1, column=1, sticky="ew")
        content_frame.columnconfigure(1, weight=1)
        #Action Frame
        action_frame = tk.Frame(add_window)
        action_frame.pack(side="bottom", padx=10, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=add_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Incluir", command=add).grid(row=0, column=1, padx=10, sticky="w")

    def edit_ttp_secondary_technique():
        #Pega id da TTP selecionada
        selected_ttp_id = ttp_id_entry.get()
        if selected_ttp_id:
            # Pega objeto da TTP selecionada
            selected_ttp = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
            if not selected_ttp:
                print("Erro: selected_ttp == None")
                return
        else:
            #Não tem TTP selecionada
            messagebox.showerror("Erro", "Selecione uma TTP.")
            return 

        #Pega valor selecionado
        selected_index_listbox = ttp_secondary_techniques_listbox.curselection()
        if not selected_index_listbox:
            return
        selected_secondary_technique = ttp_secondary_techniques_listbox.get(selected_index_listbox)
        
        #Funções de botões
        def save(event=None):
            new_secondary_technique = ttp_secondary_technique_entry.get().strip()
            #Check vazio
            if not new_secondary_technique:
                messagebox.showerror("Erro", "A Técnica Secundária não pode ser vazia.")
                return
            #Check duplicidade
            if new_secondary_technique in selected_ttp.secondary_techniques:
                messagebox.showerror("Erro", "Esta Técnica Secundária já existe.")
                return
            # Atualiza dados da TTP selecionada no objeto _threat
            idx = _threat.ttps.index(selected_ttp)
            idx_rel_tec = _threat.ttps[idx].secondary_techniques.index(selected_secondary_technique)
            _threat.ttps[idx].secondary_techniques[idx_rel_tec] = new_secondary_technique
            # Atualiza listbox (se ainda selecionada a mesma ttp)
            if selected_ttp_id == ttp_id_entry.get():
                ttp_secondary_techniques_listbox.delete(selected_index_listbox)
                ttp_secondary_techniques_listbox.insert(selected_index_listbox, new_secondary_technique)
            edit_window.destroy()

        def delete():
            if messagebox.askyesno("Excluir", "Deseja excluir esta Técnica Secundária?"):
                # Atualiza dados da TTP selecionada no objeto _threat
                idx = _threat.ttps.index(selected_ttp)
                _threat.ttps[idx].secondary_techniques.remove(selected_secondary_technique)
                # Atualiza listbox (se ainda selecionada a mesma ttp)
                if selected_ttp_id == ttp_id_entry.get():
                    ttp_secondary_techniques_listbox.delete(selected_index_listbox)
                edit_window.destroy()
            else:
                edit_window.lift()

        def consulta_nome_ttp(event=None):
            entrada = ttp_secondary_technique_entry.get()
            ttp_secondary_technique_name_entry.configure(state="normal")
            if re.match(r"T\d{4}(\.\d{3})?", entrada):
                nome = get_technique_name(attck_src, entrada)
                if nome:
                    ttp_secondary_technique_name_entry.delete(0, tk.END)
                    ttp_secondary_technique_name_entry.insert(0, nome)
                else:
                    ttp_secondary_technique_name_entry.delete(0, tk.END)
                    ttp_secondary_technique_name_entry.insert(0, "<<Nome não encontrado>>")
            else:
                ttp_secondary_technique_name_entry.delete(0, tk.END)
            ttp_secondary_technique_name_entry.configure(state="readonly")

        #Cria a janela de edição
        edit_window = tk.Toplevel(root)
        edit_window.geometry(f"500x120+{root.winfo_x()+100}+{root.winfo_y()+100}")
        edit_window.title("Editar (Sub)Técnica Secundária da " + selected_ttp_id)
        #Content Frame
        content_frame = tk.Frame(edit_window)
        content_frame.pack(fill="both", expand=True, padx=10, pady=5)
        #Column0
        tk.Label(content_frame, text="(Sub)Técnica Secundária").grid(row=0, column=0, padx=(0,10), pady=10, sticky="w")
        #tk.Label(content_frame, text="Nome").grid(row=1, column=0, padx=10, sticky="w")
        #Column1
        ttp_secondary_technique_entry = tk.Entry(content_frame, width=35)
        ttp_secondary_technique_entry.insert(0, selected_secondary_technique)
        ttp_secondary_technique_entry.grid(row=0, column=1, sticky="ew")
        ttp_secondary_technique_entry.bind("<Return>", save)
        ttp_secondary_technique_entry.bind("<KeyRelease>", consulta_nome_ttp)
        ttp_secondary_technique_entry.focus_set()
        ttp_secondary_technique_name_entry = tk.Entry(content_frame, width=35)
        ttp_secondary_technique_name_entry.configure(state="readonly")
        ttp_secondary_technique_name_entry.grid(row=1, column=1, sticky="ew")
        content_frame.columnconfigure(1, weight=1)
        #Action Frame
        action_frame = tk.Frame(edit_window)
        action_frame.pack(side="bottom", padx=10, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=edit_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Salvar", command=save).grid(row=0, column=1, padx=10, sticky="w")
        tk.Button(action_frame, text="Excluir", command=delete).grid(row=0, column=2, padx=10, sticky="w")
        consulta_nome_ttp()

    def edit_ttp_procedure():
        #Pega TTP selecionada
        selected_ttp_id = ttp_id_entry.get()
        if not selected_ttp_id:
            #Não tem TTP selecionada
            messagebox.showerror("Erro", "Selecione uma TTP.")
            return
        #Pega objeto da TTP selecionada
        selected_ttp = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
        if not selected_ttp:
            print("Erro: selected_ttp == None")
            return
        #Pega procedure inicial da TTP selecionada
        initial_ttp_procedure = ttp_procedure_text.get("1.0", tk.END).rstrip("\n")

        #Função para salvar nota da TTP
        def save(event=None):
            new_ttp_procedure = procedure_text.get("1.0", tk.END).rstrip("\n").strip()
            # Atualiza dados da TTP selecionada no objeto _threat
            idx = _threat.ttps.index(selected_ttp)
            _threat.ttps[idx].procedure = new_ttp_procedure
            # Atualiza textarea (se ainda selecionada a mesma ttp)
            if selected_ttp_id == ttp_id_entry.get():
                ttp_procedure_text.delete("1.0", tk.END)
                ttp_procedure_text.insert(tk.INSERT, new_ttp_procedure)
            edit_window.destroy()
        
        def delete():
            if messagebox.askyesno("Excluir", "Deseja excluir este Procedimento?"):
                # Atualiza dados da TTP selecionada no objeto _threat
                idx = _threat.ttps.index(selected_ttp)
                _threat.ttps[idx].procedure = ''
                # Atualiza textarea (se ainda selecionada a mesma ttp)
                if selected_ttp_id == ttp_id_entry.get():
                    ttp_procedure_text.delete("1.0", tk.END)
                edit_window.destroy()
            else:
                edit_window.lift()

        #Cria a janela de edição
        edit_window = tk.Toplevel(root)
        edit_window.geometry(f"500x300+{root.winfo_x()+100}+{root.winfo_y()+100}")
        edit_window.title("Editar Procedimento da " + selected_ttp_id)
        #Content Frame
        content_frame = tk.Frame(edit_window)
        content_frame.pack(fill="both", expand=True, padx=5, pady=5)
        content_frame.columnconfigure(1, weight=1)
        content_frame.rowconfigure(2, weight=1)
        #Column0
        tk.Label(content_frame, text="Procedimento").grid(row=0, column=0, sticky="nw", padx=10)
        tk.Button(content_frame, text="Juntar Linhas", command=lambda: join_lines(procedure_text)).grid(row=1, column=0, sticky="nw", padx=10, pady=10)
        tk.Button(content_frame, text="Separar Frases", command=lambda: separate_phrases(procedure_text)).grid(row=2, column=0, sticky="nw", padx=10)
        #Column1
        procedure_text = tk.Text(content_frame, width=20, height=5)
        procedure_text.insert(tk.END, initial_ttp_procedure)
        procedure_text.grid(row=0, column=1, rowspan=3, sticky="nsew", padx=(5,0))
        procedure_text.bind("<Control-Return>", save)
        procedure_text.focus_set()
        #Column2
        procedure_text_scrollbar = tk.Scrollbar(content_frame, orient="vertical", command=procedure_text.yview)
        procedure_text_scrollbar.grid(row=0, column=2, rowspan=3, sticky="ns", padx=(0,5))
        procedure_text.configure(yscrollcommand=procedure_text_scrollbar.set)
        #Action Frame
        action_frame = tk.Frame(edit_window)
        action_frame.pack(side="bottom", padx=5, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=edit_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Salvar", command=save).grid(row=0, column=1, padx=10, sticky="w")
        tk.Button(action_frame, text="Excluir", command=delete).grid(row=0, column=2, padx=10, sticky="w")


    def fill_ttp_tactic_name():
        #Verifica se há TTP selecionada
        selected_ttp_id = ttp_id_entry.get()
        if not selected_ttp_id:
            return
        #Pega Tactic da TTP selecionada
        tactic_id = ttp_tactic_entry.get()
        ttp_tactic_name_entry.configure(state="normal")
        ttp_tactic_name_entry.delete(0, tk.END)
        if not tactic_id:
            ttp_tactic_name_entry.configure(state="readonly")
            return
        tactic_name = get_tactic_name(attck_src, tactic_id)
        if tactic_name:
            ttp_tactic_name_entry.insert(0, tactic_name)
            save_ttp() #salva todos os campos da TTP no objeto _threat
        else:
            ttp_tactic_name_entry.insert(0, "<<Nome não encontrado>>")
        ttp_tactic_name_entry.configure(state="readonly")
    
    def fill_ttp_technique_name():
        #Verifica se há TTP selecionada
        selected_ttp_id = ttp_id_entry.get()
        if not selected_ttp_id:
            return
        #Pega Technique da TTP selecionada
        technique_id = ttp_technique_entry.get()
        ttp_technique_name_entry.configure(state="normal")
        ttp_technique_name_entry.delete(0, tk.END)
        if not technique_id:
            ttp_technique_name_entry.configure(state="readonly")
            return
        technique_name = get_technique_name(attck_src, technique_id)
        if technique_name:
            ttp_technique_name_entry.insert(0, technique_name)
            save_ttp() #salva todos os campos da TTP no objeto _threat
        else:
            ttp_technique_name_entry.insert(0, "<<Nome não encontrado>>")
        ttp_technique_name_entry.configure(state="readonly")

    def load_selected_ttp():
        """
        Carrega os dados do TTP selecionado na lista de TTPs
        """
        selection = ttps_listbox.curselection() #Retorna uma tupla com os indices dos itens selecionados
        if selection:
            selected_ttp_id = ttps_listbox.get(selection)
            selected_ttp: TTP = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
            if selected_ttp:
                clear_ttp_fields()
                ttp_id_entry.configure(state="normal")
                ttp_id_entry.insert(0, selected_ttp.ttp_id)
                ttp_id_entry.configure(state="readonly")
                ttp_tactic_entry.insert(0, selected_ttp.tactic)
                ttp_technique_entry.insert(0, selected_ttp.technique)
                ttp_procedure_text.insert("1.0", selected_ttp.procedure)
                ttp_references_listbox.insert(tk.END, *selected_ttp.references)
                ttp_secondary_techniques_listbox.insert(tk.END, *selected_ttp.secondary_techniques)
                ttp_related_ttps_listbox.insert(tk.END, *selected_ttp.related_ttps)
                ttp_chain_listbox.insert(tk.END, *selected_ttp.ttp_chain)
                ttp_notes_listbox.insert(tk.END, *selected_ttp.notes)
                #DetectionRules
                clear_rule_fields()
                rules_listbox.delete(0, tk.END)
                for rules in selected_ttp.detection_rules:
                    rules_listbox.insert(tk.END, rules.rule_id)
                #Consula e preenche Tatica e Tecnica
                fill_ttp_tactic_name()
                fill_ttp_technique_name()

    def clear_ttp_fields():
        """
        Limpa todos os campos do TTP
        """
        ttp_id_entry.configure(state="normal")
        ttp_id_entry.delete(0, tk.END)
        ttp_id_entry.configure(state="readonly")
        ttp_tactic_entry.delete(0, tk.END)
        ttp_tactic_name_entry.configure(state="normal")
        ttp_tactic_name_entry.delete(0, tk.END)
        ttp_tactic_name_entry.configure(state="readonly")
        ttp_technique_entry.delete(0, tk.END)
        ttp_technique_name_entry.configure(state="normal")
        ttp_technique_name_entry.delete(0, tk.END)
        ttp_technique_name_entry.configure(state="readonly")
        ttp_procedure_text.delete("1.0", tk.END)
        ttp_references_listbox.delete(0, tk.END)
        ttp_secondary_techniques_listbox.delete(0, tk.END)
        ttp_related_ttps_listbox.delete(0, tk.END)
        ttp_chain_listbox.delete(0, tk.END)
        ttp_notes_listbox.delete(0, tk.END)
   
    def new_ttp():
        """
        Cria um novo TTP com campos vazios
        """
        ttps_listbox.selection_clear(0, tk.END)
        clear_ttp_fields()
        new_key = generate_key("TTP")
        #Verifica se a new_key já existe na lista de TTPs e incrementa a chave se existir
        while any(ttp.ttp_id == new_key for ttp in _threat.ttps):
            new_key = generate_key("TTP", increment=True)
        #Cria novo TTP no objeto _threat
        _threat.ttps.append(TTP(new_key, "", "", "", [], [], [], [], [], []))
        #Insere TTP na lista de TTPs
        ttps_listbox.insert(tk.END, new_key)
        #Seleciona TTP na lista de TTPs
        ttps_listbox.selection_set(tk.END)
        #Carrega dados da nova TTP nos campos
        load_selected_ttp()

    def save_ttp(verbose: bool = False):
        selected_ttp_id = ttp_id_entry.get()
        if selected_ttp_id:
            # Atualiza dados da TTP no objeto _threat
            selected_ttp = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
            if selected_ttp:
                idx = _threat.ttps.index(selected_ttp)
                _threat.ttps[idx].tactic = ttp_tactic_entry.get().strip()
                _threat.ttps[idx].technique = ttp_technique_entry.get().strip()
                _threat.ttps[idx].procedure = ttp_procedure_text.get("1.0", tk.END).rstrip("\n").strip()
                _threat.ttps[idx].references = list(ttp_references_listbox.get(0, tk.END))
                _threat.ttps[idx].secondary_techniques = list(ttp_secondary_techniques_listbox.get(0, tk.END))
                _threat.ttps[idx].related_ttps = list(ttp_related_ttps_listbox.get(0, tk.END))
                _threat.ttps[idx].ttp_chain = list(ttp_chain_listbox.get(0, tk.END))
                _threat.ttps[idx].notes = list(ttp_notes_listbox.get(0, tk.END))
                if verbose:
                    messagebox.showinfo("Sucesso", "Dados da " + selected_ttp_id + " atualizados com sucesso!")
            else:
                print("Erro: selected_ttp == None")
                return
        else:
            if verbose: 
                messagebox.showerror("Erro", "O ID da TTP não pode ser vazio.\nCrie uma Nova TTP.")
            return
        
    def delete_ttp():
        selected_ttp_id = ttp_id_entry.get()
        if selected_ttp_id:
            #Verifica se a TTP pertence a algum TTP Chain
            ttps_in_ttp_chain = [ttp for ttp in _threat.ttps if selected_ttp_id in ttp.ttp_chain]
            if ttps_in_ttp_chain:
                messagebox.showerror("Erro", f"A {selected_ttp_id} não pode ser excluída pois pertence à TTP Chain de:\n{', '.join(ttp.ttp_id for ttp in ttps_in_ttp_chain)}.")
                return
            #Pega objeto da TTP selecionada
            selected_ttp = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
            if not selected_ttp:
                print("Erro: selected_ttp == None")
                return
            #Verifica se a TTP tem Detection Rules associadas
            if selected_ttp.detection_rules:
                messagebox.showerror("Erro", "A TTP selecionada tem Detection Rules associadas.\nPor favor, remova todas as regras antes de excluir a TTP.")
                return
            #Confirma a exclusão
            if messagebox.askyesno("Excluir", f"Deseja excluir a TTP {selected_ttp_id}?"):
                idx = _threat.ttps.index(selected_ttp)
                _threat.ttps.pop(idx)
                # Remove TTP da lista de TTPs e limpa campos da TTP selecionada
                idx_listbox = ttps_listbox.get(0, tk.END).index(selected_ttp_id)
                ttps_listbox.delete(idx_listbox)
                clear_ttp_fields()
        else:
            #Não tem TTP selecionada
            messagebox.showerror("Erro", "Selecione uma TTP.")
            return
    
    def clone_ttp():
        #OBS: Não inclui as Rules da TTP no clone para evitar rule_id duplicados!
        #Salva os campos da TTP
        save_ttp()
        #Pega TTP de origem
        selected_ttp_id = ttp_id_entry.get()
        if not selected_ttp_id:
            #Não tem TTP selecionada
            messagebox.showerror("Erro", "Selecione uma TTP.")
            return
        ttp_origem = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
        #Cria nova TTP vazia
        new_ttp()
        #Pega TTP nova
        selected_ttp_id = ttp_id_entry.get()
        ttp_destino = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
        #Copia atributos da TTP de origem para TTP nova
        ttp_destino.tactic = ttp_origem.tactic
        ttp_destino.technique = ttp_origem.technique
        ttp_destino.procedure = ttp_origem.procedure
        ttp_destino.references = ttp_origem.references
        ttp_destino.secondary_techniques = ttp_origem.secondary_techniques
        ttp_destino.related_ttps = ttp_origem.related_ttps
        ttp_destino.ttp_chain = ttp_origem.ttp_chain
        ttp_destino.notes = ttp_origem.notes
        #Carrega dados da nova TTP nos campos
        load_selected_ttp()

    #### Widgets do ttps_frame ####

    #Etrutura
    ttps_left_frame = tk.Frame(ttps_frame)
    ttps_left_frame.pack(side="left", anchor="nw", fill="y", expand=False, padx=5)

    ttps_right_frame = tk.LabelFrame(ttps_frame, text=t("Dados da TTP selecionada"))
    ttps_right_frame.pack(side="right", fill="both", expand=True, padx=5)

    ## Widgets do ttps_left_frame ##
    #Label título
    ttps_label = tk.Label(ttps_left_frame, text="TTPs List")
    ttps_label.grid(row=0, column=0, columnspan=2, sticky="n")

    #Listbox com scrollbar
    ttps_listbox = tk.Listbox(ttps_left_frame, selectmode="single", width=20, height=10)
    ttps_listbox.bind('<<ListboxSelect>>', lambda event: load_selected_ttp())
    ttps_listbox.bind('<Down>', lambda event: mudar_selecao_listbox(ttps_listbox, event))
    ttps_listbox.bind('<Up>', lambda event: mudar_selecao_listbox(ttps_listbox, event))
    ttps_listbox.grid(row=1, column=0, sticky="nsew")

    ttps_listbox_vscrollbar = tk.Scrollbar(ttps_left_frame, orient="vertical", command=ttps_listbox.yview)
    ttps_listbox_vscrollbar.grid(row=1, column=1, sticky="ns")
    ttps_listbox.config(yscrollcommand=ttps_listbox_vscrollbar.set)
    ttps_left_frame.grid_rowconfigure(1, weight=1)
    #Botoes
    new_ttps_button = tk.Button(ttps_left_frame, text=t("Nova TTP"), command=new_ttp)
    new_ttps_button.grid(row=2, column=0, columnspan=2, pady=5, sticky="n")
    
    ## Widgets do ttps_right_frame ##
    #Campos
    ttp_id_label = tk.Label(ttps_right_frame, text="TTP ID")
    ttp_id_entry = tk.Entry(ttps_right_frame, width=25)
    ttp_id_entry.configure(state="readonly")
    
    ttp_tactic_label = tk.Label(ttps_right_frame, text="Tactic")
    ttp_tactic_entry = tk.Entry(ttps_right_frame, width=35)
    ttp_tactic_entry.bind("<Return>", lambda event: fill_ttp_tactic_name())
    ttp_tactic_entry.bind("<FocusOut>", lambda event: fill_ttp_tactic_name())

    ttp_technique_label = tk.Label(ttps_right_frame, text="Technique")
    ttp_technique_entry = tk.Entry(ttps_right_frame, width=35)
    ttp_technique_entry.bind("<Return>", lambda event: fill_ttp_technique_name())
    ttp_technique_entry.bind("<FocusOut>", lambda event: fill_ttp_technique_name())

    ttp_procedure_label = tk.Label(ttps_right_frame, text="Procedure")
    ttp_procedure_text = tk.Text(ttps_right_frame, width=35, height=4)
    ttp_procedure_text_scrollbar = tk.Scrollbar(ttps_right_frame, orient="vertical", command=ttp_procedure_text.yview)
    ttp_procedure_text.configure(yscrollcommand=ttp_procedure_text_scrollbar.set)
    ttp_procedure_text.bind("<FocusOut>", lambda event: save_ttp())

    ttp_tactic_name_entry = tk.Entry(ttps_right_frame, width=35)
    ttp_tactic_name_entry.configure(state="readonly")
    
    ttp_technique_name_entry = tk.Entry(ttps_right_frame, width=35)
    ttp_technique_name_entry.configure(state="readonly")
    
    ttp_references_label = tk.Label(ttps_right_frame, text="References")
    ttp_references_listbox = tk.Listbox(ttps_right_frame, selectmode="single", width=25, height=3)
    ttp_references_listbox.bind('<<ListboxSelect>>', lambda event: edit_exclude_ttp_reference())
    ttp_references_listbox_scrollbar = tk.Scrollbar(ttps_right_frame, orient="vertical", command=ttp_references_listbox.yview)
    ttp_references_listbox.configure(yscrollcommand=ttp_references_listbox_scrollbar.set)
    
    ttp_secondary_techniques_label = tk.Label(ttps_right_frame, text="Secondary\nTechniques", justify="left")
    ttp_secondary_techniques_listbox = tk.Listbox(ttps_right_frame, selectmode="single", width=25, height=3)
    ttp_secondary_techniques_listbox.bind('<<ListboxSelect>>', lambda event: edit_ttp_secondary_technique())
    ttp_secondary_techniques_listbox_scrollbar = tk.Scrollbar(ttps_right_frame, orient="vertical", command=ttp_secondary_techniques_listbox.yview)
    ttp_secondary_techniques_listbox.configure(yscrollcommand=ttp_secondary_techniques_listbox_scrollbar.set)

    ttp_related_ttps_label = tk.Label(ttps_right_frame, text="Related TTPs")
    ttp_related_ttps_listbox = tk.Listbox(ttps_right_frame, selectmode="single", width=25, height=3)
    ttp_related_ttps_listbox.bind('<<ListboxSelect>>', lambda event: edit_exclude_related_ttp())
    ttp_related_ttps_listbox_scrollbar = tk.Scrollbar(ttps_right_frame, orient="vertical", command=ttp_related_ttps_listbox.yview)
    ttp_related_ttps_listbox.configure(yscrollcommand=ttp_related_ttps_listbox_scrollbar.set)

    ttp_chain_label = tk.Label(ttps_right_frame, text="TTP Chain")
    ttp_chain_listbox = tk.Listbox(ttps_right_frame, selectmode="single", width=25, height=3)
    ttp_chain_listbox.bind('<<ListboxSelect>>', lambda event: edit_exclude_ttp_chain())
    ttp_chain_listbox_scrollbar = tk.Scrollbar(ttps_right_frame, orient="vertical", command=ttp_chain_listbox.yview)
    ttp_chain_listbox.configure(yscrollcommand=ttp_chain_listbox_scrollbar.set)

    ttp_notes_label = tk.Label(ttps_right_frame, text="Notes")
    ttp_notes_listbox = tk.Listbox(ttps_right_frame, selectmode="single", width=35, height=3)
    ttp_notes_listbox.bind('<<ListboxSelect>>', lambda event: edit_ttp_note())
    ttp_notes_listbox_scrollbar = tk.Scrollbar(ttps_right_frame, orient="vertical", command=ttp_notes_listbox.yview)
    ttp_notes_listbox.configure(yscrollcommand=ttp_notes_listbox_scrollbar.set)

    #Botões
    ttp_chain_add_button = tk.Button(ttps_right_frame, text=t("Inserir >>"), command=select_ttp_chain)
    ttp_reference_add_button = tk.Button(ttps_right_frame, text=t("Inserir >>"), command=select_ttp_reference)
    ttp_note_add_button = tk.Button(ttps_right_frame, text=t("Inserir >>"), command=add_ttp_note)
    ttp_secondary_techniques_add_button = tk.Button(ttps_right_frame, text=t("Inserir >>"), command=add_ttp_secondary_technique)
    ttp_related_ttps_add_button = tk.Button(ttps_right_frame, text=t("Inserir >>"), command=select_related_ttp)
    ttp_procedure_edit_button = tk.Button(ttps_right_frame, text=t("Editar >>"), command=edit_ttp_procedure)

    #ttp_save_button = tk.Button(ttps_right_frame, text="Salvar TTP", command=lambda: save_ttp(verbose=True))
    ttp_delete_button = tk.Button(ttps_right_frame, text=t("Excluir TTP"), command=delete_ttp)
    ttp_clone_button = tk.Button(ttps_right_frame, text=t("Clonar TTP"), command=clone_ttp)

    #Organização
    #Column0
    ttp_id_label.grid(row=0, column=0, padx=5, sticky="w")
    ttp_tactic_label.grid(row=1, column=0, padx=5, sticky="w")
    ttp_tactic_name_entry.grid(row=2, column=0, columnspan=3, padx=5, sticky="ew")
    ttp_technique_label.grid(row=3, column=0, padx=5, sticky="w")
    ttp_technique_name_entry.grid(row=4, column=0, columnspan=3, padx=5, sticky="ew")
    ttp_procedure_label.grid(row=5, column=0, padx=5, sticky="w")
    ttp_procedure_edit_button.grid(row=6, column=0, padx=5, sticky="w")
    ttp_delete_button.grid(row=10, column=0, columnspan=3, padx=10, pady=5, sticky="e") #Delete button
    #Column1
    ttp_id_entry.grid(row=0, column=1, columnspan=2, padx=5, sticky="ew")
    ttp_tactic_entry.grid(row=1, column=1, columnspan=2, padx=5, sticky="ew")
    ttp_technique_entry.grid(row=3, column=1, columnspan=2, padx=5, sticky="ew")
    ttp_procedure_text.grid(row=5, column=1, rowspan=5, padx=(5, 0), sticky="nsew")
    ttps_right_frame.columnconfigure(1, weight=1)
    #Column2
    ttp_procedure_text_scrollbar.grid(row=5, column=2, rowspan=5, padx=(0,5), sticky="ns")
    #Column3
    ttp_references_label.grid(row=0, column=3, padx=5, sticky="w")
    ttp_reference_add_button.grid(row=1, column=3, padx=5, sticky="w")
    ttp_secondary_techniques_label.grid(row=2, column=3, padx=5, sticky="w")
    ttp_secondary_techniques_add_button.grid(row=3, column=3, padx=5, sticky="w")
    ttp_related_ttps_label.grid(row=4, column=3, padx=5, sticky="w")
    ttp_related_ttps_add_button.grid(row=5, column=3, padx=5, sticky="w")
    ttp_chain_label.grid(row=6, column=3, padx=5, sticky="w")
    ttp_chain_add_button.grid(row=7, column=3, padx=5, sticky="w")
    ttp_notes_label.grid(row=8, column=3, padx=5, sticky="w")
    ttp_note_add_button.grid(row=9, column=3, padx=5, sticky="w")
    ttp_clone_button.grid(row=10, column=3, columnspan=3,padx=10, pady=5, sticky="w") #Clone button
    #Column4
    ttp_references_listbox.grid(row=0, column=4, rowspan=2, padx=(5, 0), sticky="nsew")
    ttp_secondary_techniques_listbox.grid(row=2, column=4, rowspan=2, padx=(5, 0), sticky="ew")
    ttp_related_ttps_listbox.grid(row=4, column=4, rowspan=2, padx=(5, 0), sticky="ew")
    ttp_chain_listbox.grid(row=6, column=4, rowspan=2, padx=(5, 0), sticky="ew")
    ttp_notes_listbox.grid(row=8, column=4, rowspan=2, padx=(5, 0), sticky="nsew")
    #ttp_save_button.grid(row=10, column=4, columnspan=2, padx=10, pady=5, sticky="w") #Save button
    ttps_right_frame.columnconfigure(4, weight=1)
    #Column5
    ttp_references_listbox_scrollbar.grid(row=0, column=5, rowspan=2, padx=(0,5), sticky="ns")
    ttp_secondary_techniques_listbox_scrollbar.grid(row=2, column=5, rowspan=2, padx=(0,5), sticky="ns")
    ttp_related_ttps_listbox_scrollbar.grid(row=4, column=5, rowspan=2, padx=(0,5), sticky="ns")
    ttp_chain_listbox_scrollbar.grid(row=6, column=5, rowspan=2, padx=(0,5), sticky="ns")
    ttp_notes_listbox_scrollbar.grid(row=8, column=5, rowspan=2, padx=(0,5), sticky="ns")


    #### Funções de botão do stage2_frame ####
    def add_rule_platform():
        #Pega id da Rule selecionada
        selected_rule_id = rule_id_entry.get()
        if not selected_rule_id:
            #Não tem Rule selecionada
            messagebox.showerror("Erro", "Selecione uma Detection Rule.")
            return
        #Pega id da TTP selecionada
        selected_ttp_id = ttp_id_entry.get()
        if not selected_ttp_id:
            #Não tem TTP selecionada
            messagebox.showerror("Erro", "Selecione ou crie uma TTP.")
            return
        # Pega objeto da TTP selecionada
        selected_ttp = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
        if not selected_ttp:
            print("Erro: selected_ttp == None")
            return
        #Pega objeto da Rule selecionada
        idx = _threat.ttps.index(selected_ttp) #Índice da TTP selecionada
        selected_rule = next((rule for rule in _threat.ttps[idx].detection_rules if rule.rule_id == selected_rule_id), None)
        if not selected_rule:
            print("Erro: selected_rule == None")
            return
        
        #Função para adicionar nova rule_platform            
        def add(event=None):
            new_rule_platform = rule_platform_entry.get()
            if not new_rule_platform.strip():
                messagebox.showerror("Erro", "O campo está vazio.")
                return
            # Atualiza dados da Rule selecionada no objeto _threat
            idx_rule = _threat.ttps[idx].detection_rules.index(selected_rule)
            _threat.ttps[idx].detection_rules[idx_rule].platforms.append(new_rule_platform.strip())
            # Atualiza listbox (se ainda selecionada a mesma rule)
            if selected_rule_id == rule_id_entry.get():
                rule_platforms_listbox.insert(tk.END, new_rule_platform.strip())
            add_window.destroy()

        #Cria janela para adicionar nova rule_platform
        add_window = tk.Toplevel(root)
        add_window.geometry(f"450x100+{root.winfo_x()+100}+{root.winfo_y()+100}")
        add_window.title("Incluir Plataforma na Regra " + selected_rule_id)

        content_frame = tk.Frame(add_window)
        content_frame.pack(fill="both", expand=True, padx=20, pady=5)
        tk.Label(content_frame, text="Plataforma").pack(side="left", padx=10)
        rule_platform_entry = tk.Entry(content_frame)
        rule_platform_entry.pack(side="left", padx=10, fill="x", expand=True)
        rule_platform_entry.bind("<Return>", add)
        rule_platform_entry.focus_set()
        
        action_frame = tk.Frame(add_window)
        action_frame.pack(side="bottom", padx=20, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=add_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Incluir", command=add).grid(row=0, column=1, padx=10, sticky="w")
    
    def add_rule_source():
        #Pega id da Rule selecionada
        selected_rule_id = rule_id_entry.get()
        if not selected_rule_id:
            messagebox.showerror("Erro", "Selecione uma Detection Rule.")
            return
        #Pega id da TTP selecionada
        selected_ttp_id = ttp_id_entry.get()
        if not selected_ttp_id:
            #Não tem TTP selecionada
            messagebox.showerror("Erro", "Selecione ou crie uma TTP.")
            return
        # Pega objeto da TTP selecionada
        selected_ttp = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
        if not selected_ttp:
            print("Erro: selected_ttp == None")
            return
        #Pega objeto da Rule selecionada
        idx = _threat.ttps.index(selected_ttp) #Índice da TTP selecionada
        selected_rule = next((rule for rule in _threat.ttps[idx].detection_rules if rule.rule_id == selected_rule_id), None)
        if not selected_rule:
            print("Erro: selected_rule == None")
            return
        
        #Função para adicionar nova rule_source            
        def add(event=None):
            new_rule_source = rule_source_entry.get()
            if not new_rule_source.strip():
                messagebox.showerror("Erro", "O campo está vazio.")
                return
            # Atualiza dados da Rule selecionada no objeto _threat
            idx_rule = _threat.ttps[idx].detection_rules.index(selected_rule)
            _threat.ttps[idx].detection_rules[idx_rule].sources.append(new_rule_source.strip())
            # Atualiza listbox (se ainda selecionada a mesma rule)
            if selected_rule_id == rule_id_entry.get():
                rule_sources_listbox.insert(tk.END, new_rule_source.strip())
            add_window.destroy()

        #Cria janela para adicionar nova rule_source
        add_window = tk.Toplevel(root)
        add_window.geometry(f"450x100+{root.winfo_x()+100}+{root.winfo_y()+100}")
        add_window.title("Incluir Fonte na Regra " + selected_rule_id)

        content_frame = tk.Frame(add_window)
        content_frame.pack(fill="both", expand=True, padx=20, pady=5)
        tk.Label(content_frame, text="Fonte").pack(side="left", padx=10)
        rule_source_entry = tk.Entry(content_frame)
        rule_source_entry.pack(side="left", padx=10, fill="x", expand=True)
        rule_source_entry.bind("<Return>", add)
        rule_source_entry.focus_set()
        
        action_frame = tk.Frame(add_window)
        action_frame.pack(side="bottom", padx=20, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=add_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Incluir", command=add).grid(row=0, column=1, padx=10, sticky="w")

    def add_rule_coverage_technique():
        #Pega id da Rule selecionada
        selected_rule_id = rule_id_entry.get()
        if not selected_rule_id:
            messagebox.showerror("Erro", "Selecione uma Detection Rule.")
            return
        #Pega id da TTP selecionada
        selected_ttp_id = ttp_id_entry.get()
        if not selected_ttp_id:
            #Não tem TTP selecionada
            messagebox.showerror("Erro", "Selecione ou crie uma TTP.")
            return
        # Pega objeto da TTP selecionada
        selected_ttp = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
        if not selected_ttp:
            print("Erro: selected_ttp == None")
            return
        #Pega objeto da Rule selecionada
        idx = _threat.ttps.index(selected_ttp) #Índice da TTP selecionada
        selected_rule = next((rule for rule in _threat.ttps[idx].detection_rules if rule.rule_id == selected_rule_id), None)
        if not selected_rule:
            print("Erro: selected_rule == None")
            return
        
        #Função para adicionar nova rule_coverage_technique            
        def add(event=None):
            new_rule_coverage_technique = rule_coverage_technique_entry.get()
            if not new_rule_coverage_technique.strip():
                messagebox.showerror("Erro", "O campo está vazio.")
                return
            # Atualiza dados da Rule selecionada no objeto _threat
            idx_rule = _threat.ttps[idx].detection_rules.index(selected_rule)
            _threat.ttps[idx].detection_rules[idx_rule].coverage_techniques.append(new_rule_coverage_technique.strip())
            # Atualiza listbox (se ainda selecionada a mesma rule)
            if selected_rule_id == rule_id_entry.get():
                rule_coverage_techniques_listbox.insert(tk.END, new_rule_coverage_technique.strip())
            add_window.destroy()

        #Cria janela para adicionar nova rule_coverage_technique
        add_window = tk.Toplevel(root)
        add_window.geometry(f"450x100+{root.winfo_x()+100}+{root.winfo_y()+100}")
        add_window.title("Incluir Técnica coberta pela Regra " + selected_rule_id)

        content_frame = tk.Frame(add_window)
        content_frame.pack(fill="both", expand=True, padx=20, pady=5)
        tk.Label(content_frame, text="Técnica de Coberta").pack(side="left", padx=10)
        rule_coverage_technique_entry = tk.Entry(content_frame)
        rule_coverage_technique_entry.pack(side="left", padx=10, fill="x", expand=True)
        rule_coverage_technique_entry.bind("<Return>", add)
        rule_coverage_technique_entry.focus_set()
        
        action_frame = tk.Frame(add_window)
        action_frame.pack(side="bottom", padx=20, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=add_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Incluir", command=add).grid(row=0, column=1, padx=10, sticky="w")

    def add_rule_note():
        #Pega id da Rule selecionada
        selected_rule_id = rule_id_entry.get()
        if not selected_rule_id:
            messagebox.showerror("Erro", "Selecione uma Detection Rule.")
            return
        #Pega id da TTP selecionada
        selected_ttp_id = ttp_id_entry.get()
        if not selected_ttp_id:
            #Não tem TTP selecionada
            messagebox.showerror("Erro", "Selecione ou crie uma TTP.")
            return
        # Pega objeto da TTP selecionada
        selected_ttp = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
        if not selected_ttp:
            print("Erro: selected_ttp == None")
            return
        #Pega objeto da Rule selecionada
        idx = _threat.ttps.index(selected_ttp) #Índice da TTP selecionada
        selected_rule = next((rule for rule in _threat.ttps[idx].detection_rules if rule.rule_id == selected_rule_id), None)
        if not selected_rule:
            print("Erro: selected_rule == None")
            return

        #Função para adicionar nova rule_note
        def add(event=None):
            new_rule_note = rule_note_text.get("1.0", tk.END).rstrip("\n").strip()
            if not new_rule_note:
                messagebox.showerror("Erro", "O campo está vazio.")
                return
            # Atualiza dados da Rule selecionada no objeto _threat
            idx_rule = _threat.ttps[idx].detection_rules.index(selected_rule)
            _threat.ttps[idx].detection_rules[idx_rule].notes.append(new_rule_note)
            # Atualiza listbox (se ainda selecionada a mesma rule)
            if selected_rule_id == rule_id_entry.get():
                rule_notes_listbox.insert(tk.END, new_rule_note)
            add_window.destroy()

        #Cria janela para adicionar nova rule_note
        add_window = tk.Toplevel(root)
        add_window.geometry(f"450x150+{root.winfo_x()+100}+{root.winfo_y()+100}")
        add_window.title("Incluir Nota na Regra " + selected_rule_id)

        content_frame = tk.Frame(add_window)
        content_frame.pack(fill="both", expand=True, padx=5, pady=5)
        tk.Label(content_frame, text="Nota").pack(side="left", padx=10)
        rule_note_text = tk.Text(content_frame, height=5)
        rule_note_text.pack(side="left", padx=10, fill="both", expand=True)
        rule_note_text.bind("<Control-Return>", add)
        rule_note_text.focus_set()
        
        action_frame = tk.Frame(add_window)
        action_frame.pack(side="bottom", padx=5, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=add_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Incluir", command=add).grid(row=0, column=1, padx=10, sticky="w")

    def edit_rule_description():
        #Pega id da Rule selecionada
        selected_rule_id = rule_id_entry.get()
        if not selected_rule_id:
            messagebox.showerror("Erro", "Selecione uma Detection Rule.")
            return
        #Pega id da TTP selecionada
        selected_ttp_id = ttp_id_entry.get()
        if not selected_ttp_id:
            #Não tem TTP selecionada
            messagebox.showerror("Erro", "Selecione ou crie uma TTP.")
            return
        # Pega objeto da TTP selecionada
        selected_ttp = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
        if not selected_ttp:
            print("Erro: selected_ttp == None")
            return
        #Pega objeto da Rule selecionada
        idx = _threat.ttps.index(selected_ttp) #Índice da TTP selecionada
        selected_rule = next((rule for rule in _threat.ttps[idx].detection_rules if rule.rule_id == selected_rule_id), None)
        if not selected_rule:
            print("Erro: selected_rule == None")
            return
        idx_rule = _threat.ttps[idx].detection_rules.index(selected_rule)
        #Pega description inicial da Rule selecionada
        initial_rule_description = rule_description_text.get("1.0", tk.END).rstrip("\n")
        
        #Função para salvar rule_query
        def save(event=None):
            new_rule_description = description_text.get("1.0", tk.END).rstrip("\n").strip()
            # Atualiza dados da Rule selecionada no objeto _threat
            idx_rule = _threat.ttps[idx].detection_rules.index(selected_rule)
            _threat.ttps[idx].detection_rules[idx_rule].description = new_rule_description
            # Atualiza listbox (se ainda selecionada a mesma rule)
            if selected_rule_id == rule_id_entry.get():
                rule_description_text.delete("1.0", tk.END)
                rule_description_text.insert(tk.INSERT, new_rule_description)
            edit_window.destroy()

        #Função para excluir rule_query
        def delete():
            if messagebox.askyesno("Excluir", "Deseja excluir esta Descrição da Regra?"):
                # Atualiza dados da Rule selecionada no objeto _threat
                idx_rule = _threat.ttps[idx].detection_rules.index(selected_rule)
                _threat.ttps[idx].detection_rules[idx_rule].description = ''
                # Atualiza listbox (se ainda selecionada a mesma rule)
                if selected_rule_id == rule_id_entry.get():
                    rule_description_text.delete("1.0", tk.END)
                edit_window.destroy()
            else:
                edit_window.lift()

        #Cria a janela de edição
        edit_window = tk.Toplevel(root)
        edit_window.geometry(f"500x250+{root.winfo_x()+100}+{root.winfo_y()+100}")
        edit_window.title("Editar Descrição da Regra " + selected_rule_id)

        content_frame = tk.Frame(edit_window)
        content_frame.pack(fill="both", expand=True, padx=5, pady=5)
        content_frame.columnconfigure(1, weight=1)
        content_frame.rowconfigure(2, weight=1)
        #Column0
        tk.Label(content_frame, text="Descrição").grid(row=0, column=0, sticky="nw", padx=10)
        tk.Button(content_frame, text="Juntar Linhas", command=lambda: join_lines(description_text)).grid(row=1, column=0, sticky="nw", padx=10, pady=10)
        tk.Button(content_frame, text="Separar Frases", command=lambda: separate_phrases(description_text)).grid(row=2, column=0, sticky="nw", padx=10)
        #Column1
        description_text = tk.Text(content_frame, width=20, height=5)
        description_text.insert(tk.END, initial_rule_description)
        description_text.grid(row=0, column=1, rowspan=3, sticky="nsew", padx=(5,0))
        description_text.bind("<Control-Return>", save)
        description_text.focus_set()
        #Column2
        description_text_scrollbar = tk.Scrollbar(content_frame, orient="vertical", command=description_text.yview)
        description_text_scrollbar.grid(row=0, column=2, rowspan=3, sticky="ns", padx=(0,5))
        description_text.configure(yscrollcommand=description_text_scrollbar.set)
        
        action_frame = tk.Frame(edit_window)
        action_frame.pack(side="bottom", padx=5, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=edit_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Salvar", command=save).grid(row=0, column=1, padx=10, sticky="w")
        tk.Button(action_frame, text="Excluir", command=delete).grid(row=0, column=2, padx=10, sticky="w")


    def edit_rule_platform():
        #Pega id da Rule selecionada
        selected_rule_id = rule_id_entry.get()
        if not selected_rule_id:
            messagebox.showerror("Erro", "Selecione uma Detection Rule.")
            return
        #Pega id da TTP selecionada
        selected_ttp_id = ttp_id_entry.get()
        if not selected_ttp_id:
            #Não tem TTP selecionada
            messagebox.showerror("Erro", "Selecione ou crie uma TTP.")
            return
        # Pega objeto da TTP selecionada
        selected_ttp = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
        if not selected_ttp:
            print("Erro: selected_ttp == None")
            return
        #Pega objeto da Rule selecionada
        idx = _threat.ttps.index(selected_ttp) #Índice da TTP selecionada
        selected_rule = next((rule for rule in _threat.ttps[idx].detection_rules if rule.rule_id == selected_rule_id), None)
        if not selected_rule:
            print("Erro: selected_rule == None")
            return
        #Pegas paltform da Rule selecionada
        selected_index_listbox = rule_platforms_listbox.curselection()
        if not selected_index_listbox:
            return
        selected_rule_platform = rule_platforms_listbox.get(selected_index_listbox)
               
        #Função para salvar rule_platform
        def save(event=None):
            new_rule_platform = rule_platform_entry.get().strip()
            if not new_rule_platform:
                messagebox.showerror("Erro", "A plataforma pode ser vazia.")
                return
            # Atualiza dados da Rule selecionada no objeto _threat
            idx = _threat.ttps.index(selected_ttp)
            idx_rule = _threat.ttps[idx].detection_rules.index(selected_rule)
            idx_platform = _threat.ttps[idx].detection_rules[idx_rule].platforms.index(selected_rule_platform)
            _threat.ttps[idx].detection_rules[idx_rule].platforms[idx_platform] = new_rule_platform
            # Atualiza listbox (se ainda selecionada a mesma rule)
            if selected_rule_id == rule_id_entry.get():
                rule_platforms_listbox.delete(selected_index_listbox)
                rule_platforms_listbox.insert(selected_index_listbox, new_rule_platform)
            edit_window.destroy()

        #Função para excluir rule_platform
        def delete():
            if messagebox.askyesno("Excluir", "Deseja excluir esta plataforma da Regra?"):
                # Atualiza dados da Rule selecionada no objeto _threat
                idx = _threat.ttps.index(selected_ttp)
                idx_rule = _threat.ttps[idx].detection_rules.index(selected_rule)
                _threat.ttps[idx].detection_rules[idx_rule].platforms.remove(selected_rule_platform)
                # Atualiza listbox (se ainda selecionada a mesma rule)
                if selected_rule_id == rule_id_entry.get():
                    rule_platforms_listbox.delete(selected_index_listbox)
                edit_window.destroy()
            else:
                edit_window.lift()

        #Cria a janela de edição
        edit_window = tk.Toplevel(root)
        edit_window.geometry(f"450x150+{root.winfo_x()+100}+{root.winfo_y()+100}")
        edit_window.title("Editar Plataforma da Regra " + selected_rule_id)

        content_frame = tk.Frame(edit_window)
        content_frame.pack(fill="both", expand=True, padx=5, pady=5)

        tk.Label(content_frame, text="Plataforma").pack(side="left", padx=10)
        rule_platform_entry = tk.Entry(content_frame)
        rule_platform_entry.insert(0, selected_rule_platform)
        rule_platform_entry.pack(side="left", padx=10, fill="x", expand=True)
        rule_platform_entry.bind("<Return>", save)
        rule_platform_entry.focus_set()

        action_frame = tk.Frame(edit_window)
        action_frame.pack(side="bottom", padx=20, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=edit_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Salvar", command=save).grid(row=0, column=1, padx=10, sticky="w")
        tk.Button(action_frame, text="Excluir", command=delete).grid(row=0, column=2, padx=10, sticky="w")

    def edit_rule_source():
        #Pega id da Rule selecionada
        selected_rule_id = rule_id_entry.get()
        if not selected_rule_id:
            messagebox.showerror("Erro", "Selecione uma Detection Rule.")
            return
        #Pega id da TTP selecionada
        selected_ttp_id = ttp_id_entry.get()
        if not selected_ttp_id:
            #Não tem TTP selecionada
            messagebox.showerror("Erro", "Selecione ou crie uma TTP.")
            return
        # Pega objeto da TTP selecionada
        selected_ttp = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
        if not selected_ttp:
            print("Erro: selected_ttp == None")
            return
        #Pega objeto da Rule selecionada
        idx = _threat.ttps.index(selected_ttp) #Índice da TTP selecionada
        selected_rule = next((rule for rule in _threat.ttps[idx].detection_rules if rule.rule_id == selected_rule_id), None)
        if not selected_rule:
            print("Erro: selected_rule == None")
            return
        #Pega source da Rule selecionada
        selected_index_listbox = rule_sources_listbox.curselection()
        if not selected_index_listbox:
            return
        selected_rule_source = rule_sources_listbox.get(selected_index_listbox)
               
        #Função para salvar rule_source
        def save(event=None):
            new_rule_source = rule_source_entry.get().strip()
            if not new_rule_source:
                messagebox.showerror("Erro", "A fonte pode ser vazia.")
                return
            # Atualiza dados da Rule selecionada no objeto _threat
            idx = _threat.ttps.index(selected_ttp)
            idx_rule = _threat.ttps[idx].detection_rules.index(selected_rule)
            idx_source = _threat.ttps[idx].detection_rules[idx_rule].sources.index(selected_rule_source)
            _threat.ttps[idx].detection_rules[idx_rule].sources[idx_source] = new_rule_source
            # Atualiza listbox (se ainda selecionada a mesma rule)
            if selected_rule_id == rule_id_entry.get():
                rule_sources_listbox.delete(selected_index_listbox)
                rule_sources_listbox.insert(selected_index_listbox, new_rule_source)
            edit_window.destroy()

        #Função para excluir rule_source
        def delete():
            if messagebox.askyesno("Excluir", "Deseja excluir esta fonte da Regra?"):
                # Atualiza dados da Rule selecionada no objeto _threat
                idx = _threat.ttps.index(selected_ttp)
                idx_rule = _threat.ttps[idx].detection_rules.index(selected_rule)
                _threat.ttps[idx].detection_rules[idx_rule].sources.remove(selected_rule_source)
                # Atualiza listbox (se ainda selecionada a mesma rule)
                if selected_rule_id == rule_id_entry.get():
                    rule_sources_listbox.delete(selected_index_listbox)
                edit_window.destroy()
            else:
                edit_window.lift()

        #Cria a janela de edição
        edit_window = tk.Toplevel(root)
        edit_window.geometry(f"450x150+{root.winfo_x()+100}+{root.winfo_y()+100}")
        edit_window.title("Editar Fonte da Regra " + selected_rule_id)

        content_frame = tk.Frame(edit_window)
        content_frame.pack(fill="both", expand=True, padx=5, pady=5)

        tk.Label(content_frame, text="Fonte").pack(side="left", padx=10)
        rule_source_entry = tk.Entry(content_frame)
        rule_source_entry.insert(0, selected_rule_source)
        rule_source_entry.pack(side="left", padx=10, fill="x", expand=True)
        rule_source_entry.bind("<Return>", save)
        rule_source_entry.focus_set()

        action_frame = tk.Frame(edit_window)
        action_frame.pack(side="bottom", padx=20, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=edit_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Salvar", command=save).grid(row=0, column=1, padx=10, sticky="w")
        tk.Button(action_frame, text="Excluir", command=delete).grid(row=0, column=2, padx=10, sticky="w")

    def edit_rule_coverage_technique():
        #Pega id da Rule selecionada
        selected_rule_id = rule_id_entry.get()
        if not selected_rule_id:
            messagebox.showerror("Erro", "Selecione uma Detection Rule.")
            return
        #Pega id da TTP selecionada
        selected_ttp_id = ttp_id_entry.get()
        if not selected_ttp_id:
            #Não tem TTP selecionada
            messagebox.showerror("Erro", "Selecione ou crie uma TTP.")
            return
        # Pega objeto da TTP selecionada
        selected_ttp = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
        if not selected_ttp:
            print("Erro: selected_ttp == None")
            return
        #Pega objeto da Rule selecionada
        idx = _threat.ttps.index(selected_ttp) #Índice da TTP selecionada
        selected_rule = next((rule for rule in _threat.ttps[idx].detection_rules if rule.rule_id == selected_rule_id), None)
        if not selected_rule:
            print("Erro: selected_rule == None")
            return
        #Pega Técnicas de Cobertura da Rule selecionada
        selected_coverage_techniques = selected_rule.coverage_techniques
        if not selected_coverage_techniques:
            messagebox.showerror("Erro", "Esta Regra não tem Covered Techniques.")
            return
        #Pega Regra selecionada na listbox
        selected_index_listbox = rule_coverage_techniques_listbox.curselection()
        if not selected_index_listbox:
            return
        selected_rule_coverage_technique = rule_coverage_techniques_listbox.get(selected_index_listbox)
        
        
        #Função para salvar rule_coverage_technique
        def save(event=None):
            new_rule_coverage_technique = rule_coverage_technique_entry.get().strip()
            if not new_rule_coverage_technique:
                messagebox.showerror("Erro", "O campo está vazio.")
                return
            # Atualiza dados da Rule selecionada no objeto _threat
            idx = _threat.ttps.index(selected_ttp)
            idx_rule = _threat.ttps[idx].detection_rules.index(selected_rule)
            idx_coverage_technique = _threat.ttps[idx].detection_rules[idx_rule].coverage_techniques.index(selected_rule_coverage_technique)
            _threat.ttps[idx].detection_rules[idx_rule].coverage_techniques[idx_coverage_technique] = new_rule_coverage_technique
            # Atualiza listbox (se ainda selecionada a mesma rule)
            if selected_rule_id == rule_id_entry.get():
                rule_coverage_techniques_listbox.delete(selected_index_listbox)
                rule_coverage_techniques_listbox.insert(selected_index_listbox, new_rule_coverage_technique)
            edit_window.destroy()

        #Função para excluir rule_coverage_technique
        def delete():
            if messagebox.askyesno("Excluir", "Deseja excluir esta Técnica de Cobertura da Regra?"):
                # Atualiza dados da Rule selecionada no objeto _threat
                idx = _threat.ttps.index(selected_ttp)
                idx_rule = _threat.ttps[idx].detection_rules.index(selected_rule)
                _threat.ttps[idx].detection_rules[idx_rule].coverage_techniques.remove(selected_rule_coverage_technique)
                # Atualiza listbox (se ainda selecionada a mesma rule)
                if selected_rule_id == rule_id_entry.get():
                    rule_coverage_techniques_listbox.delete(selected_index_listbox)
                edit_window.destroy()
            else:
                edit_window.lift()

        #Cria a janela de edição
        edit_window = tk.Toplevel(root)
        edit_window.geometry(f"450x150+{root.winfo_x()+100}+{root.winfo_y()+100}")
        edit_window.title("Editar Técnica de Cobertura da Regra " + selected_rule_id)

        content_frame = tk.Frame(edit_window)
        content_frame.pack(fill="both", expand=True, padx=5, pady=5)

        tk.Label(content_frame, text="Técnica de Cobertura").pack(side="left", padx=10)
        rule_coverage_technique_entry = tk.Entry(content_frame)
        rule_coverage_technique_entry.insert(0, selected_rule_coverage_technique)
        rule_coverage_technique_entry.pack(side="left", padx=10, fill="x", expand=True)
        rule_coverage_technique_entry.bind("<Return>", save)
        rule_coverage_technique_entry.focus_set()

        action_frame = tk.Frame(edit_window)
        action_frame.pack(side="bottom", padx=20, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=edit_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Salvar", command=save).grid(row=0, column=1, padx=10, sticky="w")
        tk.Button(action_frame, text="Excluir", command=delete).grid(row=0, column=2, padx=10, sticky="w")

    def edit_rule_note():
        #Pega id da Rule selecionada
        selected_rule_id = rule_id_entry.get()
        if not selected_rule_id:
            messagebox.showerror("Erro", "Selecione uma Detection Rule.")
            return
        #Pega id da TTP selecionada
        selected_ttp_id = ttp_id_entry.get()
        if not selected_ttp_id:
            #Não tem TTP selecionada
            messagebox.showerror("Erro", "Selecione ou crie uma TTP.")
            return
        # Pega objeto da TTP selecionada
        selected_ttp = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
        if not selected_ttp:
            print("Erro: selected_ttp == None")
            return
        #Pega objeto da Rule selecionada
        idx = _threat.ttps.index(selected_ttp) #Índice da TTP selecionada
        selected_rule = next((rule for rule in _threat.ttps[idx].detection_rules if rule.rule_id == selected_rule_id), None)
        if not selected_rule:
            print("Erro: selected_rule == None")
            return
        idx_rule = _threat.ttps[idx].detection_rules.index(selected_rule)
        
        #Pega note da Rule selecionada
        selected_index_listbox = rule_notes_listbox.curselection()
        if not selected_index_listbox:
            return
        selected_rule_note = rule_notes_listbox.get(selected_index_listbox)
        
               
        #Função para salvar rule_note
        def save(event=None):
            new_rule_note = rule_note_text.get("1.0", tk.END).rstrip("\n").strip()
            if not new_rule_note:
                messagebox.showerror("Erro", "O campo está vazio.")
                return
            # Atualiza dados da Rule selecionada no objeto _threat
            idx_note = _threat.ttps[idx].detection_rules[idx_rule].notes.index(selected_rule_note)
            _threat.ttps[idx].detection_rules[idx_rule].notes[idx_note] = new_rule_note
            # Atualiza listbox (se ainda selecionada a mesma rule)
            if selected_rule_id == rule_id_entry.get():
                rule_notes_listbox.delete(selected_index_listbox)
                rule_notes_listbox.insert(selected_index_listbox, new_rule_note)
            edit_window.destroy()

        #Função para excluir rule_note
        def delete():
            if messagebox.askyesno("Excluir", "Deseja excluir esta nota da Regra?"):
                # Atualiza dados da Rule selecionada no objeto _threat
                _threat.ttps[idx].detection_rules[idx_rule].notes.remove(selected_rule_note)
                # Atualiza listbox (se ainda selecionada a mesma rule)
                if selected_rule_id == rule_id_entry.get():
                    rule_notes_listbox.delete(selected_index_listbox)
                edit_window.destroy()
            else:
                edit_window.lift()

        #Cria a janela de edição
        edit_window = tk.Toplevel(root)
        edit_window.geometry(f"450x150+{root.winfo_x()+100}+{root.winfo_y()+100}")
        edit_window.title("Editar Nota da Regra " + selected_rule_id)

        content_frame = tk.Frame(edit_window)
        content_frame.pack(fill="both", expand=True, padx=5, pady=5)

        tk.Label(content_frame, text="Nota").pack(side="left", padx=10)
        rule_note_text = tk.Text(content_frame, height=5)
        rule_note_text.insert("1.0", selected_rule_note)
        rule_note_text.pack(side="left", padx=10, fill="both", expand=True)
        rule_note_text.bind("<Control-Return>", save)
        rule_note_text.focus_set()

        action_frame = tk.Frame(edit_window)
        action_frame.pack(side="bottom", padx=20, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=edit_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Salvar", command=save).grid(row=0, column=1, padx=10, sticky="w")
        tk.Button(action_frame, text="Excluir", command=delete).grid(row=0, column=2, padx=10, sticky="w")

    def edit_rule_query():
        #Pega id da Rule selecionada
        selected_rule_id = rule_id_entry.get()
        if not selected_rule_id:
            messagebox.showerror("Erro", "Selecione uma Detection Rule.")
            return
        #Pega id da TTP selecionada
        selected_ttp_id = ttp_id_entry.get()
        if not selected_ttp_id:
            #Não tem TTP selecionada
            messagebox.showerror("Erro", "Selecione ou crie uma TTP.")
            return
        # Pega objeto da TTP selecionada
        selected_ttp = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
        if not selected_ttp:
            print("Erro: selected_ttp == None")
            return
        #Pega objeto da Rule selecionada
        idx = _threat.ttps.index(selected_ttp) #Índice da TTP selecionada
        selected_rule = next((rule for rule in _threat.ttps[idx].detection_rules if rule.rule_id == selected_rule_id), None)
        if not selected_rule:
            print("Erro: selected_rule == None")
            return
        idx_rule = _threat.ttps[idx].detection_rules.index(selected_rule)
        #Pega query inicial da Rule selecionada
        initial_rule_query = rule_query_text.get("1.0", tk.END).rstrip("\n")
        
        #Função para salvar rule_query
        def save(event=None):
            new_rule_query = query_text.get("1.0", tk.END).rstrip("\n").strip()
            # Atualiza dados da Rule selecionada no objeto _threat
            idx_rule = _threat.ttps[idx].detection_rules.index(selected_rule)
            _threat.ttps[idx].detection_rules[idx_rule].query = new_rule_query
            # Atualiza listbox (se ainda selecionada a mesma rule)
            if selected_rule_id == rule_id_entry.get():
                rule_query_text.delete("1.0", tk.END)
                rule_query_text.insert(tk.INSERT, new_rule_query)
            edit_window.destroy()

        #Função para excluir rule_query
        def delete():
            if messagebox.askyesno("Excluir", "Deseja excluir esta Query da Regra?"):
                # Atualiza dados da Rule selecionada no objeto _threat
                idx_rule = _threat.ttps[idx].detection_rules.index(selected_rule)
                _threat.ttps[idx].detection_rules[idx_rule].query = ''
                # Atualiza listbox (se ainda selecionada a mesma rule)
                if selected_rule_id == rule_id_entry.get():
                    rule_query_text.delete("1.0", tk.END)
                edit_window.destroy()
            else:
                edit_window.lift()

        #Cria a janela de edição
        edit_window = tk.Toplevel(root)
        edit_window.geometry(f"500x250+{root.winfo_x()+100}+{root.winfo_y()+100}")
        edit_window.title("Editar Query da Regra " + selected_rule_id)

        content_frame = tk.Frame(edit_window)
        content_frame.pack(fill="both", expand=True, padx=5, pady=5)
        content_frame.columnconfigure(1, weight=1)
        content_frame.rowconfigure(2, weight=1)
        #Column0
        tk.Label(content_frame, text="Query").grid(row=0, column=0, sticky="nw", padx=10)
        tk.Button(content_frame, text="Juntar Linhas", command=lambda: join_lines(query_text)).grid(row=1, column=0, sticky="nw", padx=10, pady=10)
        tk.Button(content_frame, text="Separar Frases", command=lambda: separate_phrases(query_text)).grid(row=2, column=0, sticky="nw", padx=10)
        #Column1
        query_text = tk.Text(content_frame, width=20, height=5)
        query_text.insert(tk.END, initial_rule_query)
        query_text.grid(row=0, column=1, rowspan=3, sticky="nsew", padx=(5,0))
        query_text.bind("<Control-Return>", save)
        query_text.focus_set()
        #Column2
        query_text_scrollbar = tk.Scrollbar(content_frame, orient="vertical", command=query_text.yview)
        query_text_scrollbar.grid(row=0, column=2, rowspan=3, sticky="ns", padx=(0,5))
        query_text.configure(yscrollcommand=query_text_scrollbar.set)
        
        action_frame = tk.Frame(edit_window)
        action_frame.pack(side="bottom", padx=5, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=edit_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Salvar", command=save).grid(row=0, column=1, padx=10, sticky="w")
        tk.Button(action_frame, text="Excluir", command=delete).grid(row=0, column=2, padx=10, sticky="w")


    def load_selected_rule():
        selected_ttp_id = ttp_id_entry.get()
        if selected_ttp_id:
            selected_ttp = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
            if not selected_ttp:
                print("Erro: selected_ttp == None")
                return
            selection = rules_listbox.curselection() #Retorna uma tupla com os indices dos itens selecionados
            if selection:
                selected_rule_id = rules_listbox.get(selection)
                selected_rule: DetectionRule = next((rule for rule in selected_ttp.detection_rules if rule.rule_id == selected_rule_id), None)
                if selected_rule:
                    clear_rule_fields()
                    rule_id_entry.configure(state="normal")
                    rule_id_entry.insert(0, selected_rule.rule_id)
                    rule_id_entry.configure(state="readonly")
                    rule_creation_date_entry.configure(state="normal")
                    rule_creation_date_entry.insert(0, selected_rule.creation_date)
                    rule_creation_date_entry.configure(state="readonly")
                    rule_update_date_entry.configure(state="normal")
                    rule_update_date_entry.insert(0, selected_rule.update_date)
                    rule_update_date_entry.configure(state="readonly")
                    rule_description_text.insert("1.0", selected_rule.description)
                    rule_platforms_listbox.insert(tk.END, *selected_rule.platforms)
                    rule_coverage_techniques_listbox.insert(tk.END, *selected_rule.coverage_techniques)
                    rule_reference_ttp_entry.configure(state="normal")
                    rule_reference_ttp_entry.insert(0, selected_rule.reference_ttp)
                    rule_reference_ttp_entry.configure(state="readonly")
                    rule_language_entry.insert(0, selected_rule.language)
                    rule_query_text.insert("1.0", selected_rule.query)
                    rule_sources_listbox.insert(tk.END, *selected_rule.sources)
                    rule_notes_listbox.insert(tk.END, *selected_rule.notes)
                    #Validation fields
                    validation_detectionrule_id_entry.configure(state="normal")
                    validation_detectionrule_id_entry.insert(0, selected_rule.rule_id)
                    validation_detectionrule_id_entry.configure(state="readonly")
                    selected_validation : Validation = selected_rule.validation
                    if selected_validation:
                        validation_status_combobox.set(selected_validation.status.lower())
                        validation_update_date_entry.configure(state="normal")
                        validation_update_date_entry.insert(0, selected_validation.update_date)
                        validation_update_date_entry.configure(state="readonly")
                        validation_dataset_entry.insert(0, selected_validation.dataset)
                        validation_references_listbox.insert(tk.END, *selected_validation.references)
                        validation_notes_listbox.insert(tk.END, *selected_validation.notes)
        else:
            print("Erro: selected_ttp_id == None")
            return

    def clear_rule_fields():
        rule_id_entry.configure(state="normal")
        rule_id_entry.delete(0, tk.END)
        rule_id_entry.configure(state="readonly")
        rule_creation_date_entry.configure(state="normal")
        rule_creation_date_entry.delete(0, tk.END)
        rule_creation_date_entry.configure(state="readonly")
        rule_update_date_entry.configure(state="normal")
        rule_update_date_entry.delete(0, tk.END)
        rule_update_date_entry.configure(state="readonly")
        rule_description_text.delete("1.0", tk.END)
        rule_platforms_listbox.delete(0, tk.END)
        rule_coverage_techniques_listbox.delete(0, tk.END)
        rule_reference_ttp_entry.configure(state="normal")
        rule_reference_ttp_entry.delete(0, tk.END)
        rule_reference_ttp_entry.configure(state="readonly")
        rule_language_entry.delete(0, tk.END)
        rule_query_text.delete("1.0", tk.END)
        rule_sources_listbox.delete(0, tk.END)
        rule_notes_listbox.delete(0, tk.END)
        #Validation fields
        validation_detectionrule_id_entry.configure(state="normal")
        validation_detectionrule_id_entry.delete(0, tk.END)
        validation_detectionrule_id_entry.configure(state="readonly")
        clear_validation_fields()

    def new_rule():
        selected_ttp_id = ttp_id_entry.get()
        if selected_ttp_id:
            selected_ttp = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
            if not selected_ttp:
                print("Erro: selected_ttp == None")
                return
            rules_listbox.selection_clear(0, tk.END)
            clear_rule_fields()
            new_key = generate_key("DTR")
            #Verifica se a new_key já existe na lista de Regras e incrementa a chave se existir
            while any(rule.rule_id == new_key for rule in selected_ttp.detection_rules):
                new_key = generate_key("DTR", increment=True)
            #Cria novo DetectionRule no TTP selecionado do objeto _threat
            idx = _threat.ttps.index(selected_ttp) #Índice da TTP selecionada
            _threat.ttps[idx].detection_rules.append(DetectionRule(new_key, get_today_date(), "", "", [], [], "", "", [], selected_ttp_id, [], Validation(VALIDATION_STATUS_LIST[0],"","",[],[])))
            #Importa technique da TTP para o Coverage Technique, se existir
            if selected_ttp.technique:
                _threat.ttps[idx].detection_rules[-1].coverage_techniques.append(selected_ttp.technique)
            #Insere Rule na lista de Regras
            rules_listbox.insert(tk.END, new_key)
            #Seleciona Rule na lista de Regras
            rules_listbox.selection_set(tk.END)
            #Carrega dados da nova Rule nos campos
            load_selected_rule()
        else:
            messagebox.showerror("Erro", "Selecione ou crie uma TTP.")
            return

    def delete_rule():
        selected_ttp_id = ttp_id_entry.get()
        if selected_ttp_id:
            selected_ttp = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
            if not selected_ttp:
                print("Erro: selected_ttp == None")
                return
            selected_rule_id = rule_id_entry.get()
            if selected_rule_id:
                #Pega objeto da Rule selecionada
                idx = _threat.ttps.index(selected_ttp) #Índice da TTP selecionada
                selected_rule = next((rule for rule in _threat.ttps[idx].detection_rules if rule.rule_id == selected_rule_id), None)
                if not selected_rule:
                    print("Erro: selected_rule == None")
                    return
                idx_rule = _threat.ttps[idx].detection_rules.index(selected_rule)
                if messagebox.askyesno("Excluir", f"Deseja excluir a Regra {selected_rule_id}?"):
                    _threat.ttps[idx].detection_rules.pop(idx_rule)
                    # Remove Rule da lista de Regras e limpa campos da Rule selecionada
                    idx_listbox = rules_listbox.get(0, tk.END).index(selected_rule_id)
                    rules_listbox.delete(idx_listbox)
                    clear_rule_fields()
            else:
                #Não tem Rule selecionada
                messagebox.showerror("Erro", "Selecione uma Regra.")
                return
        else:
            messagebox.showerror("Erro", "Selecione ou crie uma TTP.")
            return

    def save_rule(verbose: bool = False):
        selected_ttp_id = ttp_id_entry.get()
        if selected_ttp_id:
            selected_ttp = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
            if not selected_ttp:
                print("Erro: selected_ttp == None")
                return
            selected_rule_id = rule_id_entry.get()
            if selected_rule_id:
                #Pega objeto da Rule selecionada
                idx = _threat.ttps.index(selected_ttp) #Índice da TTP selecionada
                selected_rule = next((rule for rule in _threat.ttps[idx].detection_rules if rule.rule_id == selected_rule_id), None)
                if not selected_rule:
                    print("Erro: selected_rule == None")
                    return
                idx_rule = _threat.ttps[idx].detection_rules.index(selected_rule)
                #Atualiza rule_update_date_entry
                rule_update_date_entry.configure(state="normal")
                rule_update_date_entry.delete(0, tk.END)
                rule_update_date_entry.insert(0, get_today_date())
                rule_update_date_entry.configure(state="readonly")
                #Atualiza os campos do objeto da Rule
                _threat.ttps[idx].detection_rules[idx_rule].creation_date = rule_creation_date_entry.get()
                _threat.ttps[idx].detection_rules[idx_rule].update_date = rule_update_date_entry.get()
                _threat.ttps[idx].detection_rules[idx_rule].description = rule_description_text.get("1.0", tk.END).strip()
                _threat.ttps[idx].detection_rules[idx_rule].platforms = list(rule_platforms_listbox.get(0, tk.END))
                _threat.ttps[idx].detection_rules[idx_rule].coverage_techniques = list(rule_coverage_techniques_listbox.get(0, tk.END))
                _threat.ttps[idx].detection_rules[idx_rule].reference_ttp = rule_reference_ttp_entry.get()
                _threat.ttps[idx].detection_rules[idx_rule].language = rule_language_entry.get()
                _threat.ttps[idx].detection_rules[idx_rule].query = rule_query_text.get("1.0", tk.END).strip()
                _threat.ttps[idx].detection_rules[idx_rule].sources = list(rule_sources_listbox.get(0, tk.END))
                _threat.ttps[idx].detection_rules[idx_rule].notes = list(rule_notes_listbox.get(0, tk.END))
                if verbose: 
                    messagebox.showinfo("Sucesso", "Dados da Regra " + selected_rule_id + " atualizados com sucesso!")
            else:
                #Não tem Rule selecionada
                if verbose:
                    messagebox.showerror("Erro", "Selecione uma Regra.")
                return
        else:
            if verbose: 
                messagebox.showerror("Erro", "Selecione ou crie uma TTP.")
            return
    
    #### Estrutura do stage2_frame ####

    #Estrutura
    rules_left_frame = tk.Frame(stage2_frame)
    rules_left_frame.pack(side="left", anchor="nw", fill="y", expand=False, padx=5)

    rules_right_frame = tk.LabelFrame(stage2_frame, text=t("Dados da Regra de Detecção selecionada"))
    rules_right_frame.pack(side="right", fill="both", expand=True, padx=5, pady=5)

    ## Widgets do rules_left_frame ##
    #Label título
    rules_label = tk.Label(rules_left_frame, text="Detection Rules List")
    rules_label.grid(row=0, column=0, columnspan=2, sticky="n")

    #Listbox com scrollbar
    rules_listbox = tk.Listbox(rules_left_frame, selectmode="single")
    rules_listbox.bind("<<ListboxSelect>>", lambda event: load_selected_rule())
    rules_listbox.bind('<Down>', lambda event: mudar_selecao_listbox(rules_listbox, event))
    rules_listbox.bind('<Up>', lambda event: mudar_selecao_listbox(rules_listbox, event))
    rules_listbox.grid(row=1, column=0, sticky="nsew")
    
    rules_listbox_scrollbar = tk.Scrollbar(rules_left_frame, orient="vertical", command=rules_listbox.yview)
    rules_listbox_scrollbar.grid(row=1, column=1, sticky="ns")
    rules_listbox.config(yscrollcommand=rules_listbox_scrollbar.set)
    rules_left_frame.grid_rowconfigure(1, weight=1)

    #Botoes
    new_rule_button = tk.Button(rules_left_frame, text=t("Nova Regra"), command=new_rule)
    new_rule_button.grid(row=2, column=0, columnspan=2, pady=5, sticky="n")

    ## Widgets do rules_right_frame ##
    #Campos
    rule_id_label = tk.Label(rules_right_frame, text="ID")
    rule_id_entry = tk.Entry(rules_right_frame, width=25)
    rule_id_entry.configure(state="readonly")

    rule_creation_date_label = tk.Label(rules_right_frame, text="Creation Date")
    rule_creation_date_entry = tk.Entry(rules_right_frame, width=25)
    rule_creation_date_entry.configure(state="readonly")

    rule_updated_date_label = tk.Label(rules_right_frame, text="Update Date")
    rule_update_date_entry = tk.Entry(rules_right_frame, width=25)
    rule_update_date_entry.configure(state="readonly")

    rule_description_label = tk.Label(rules_right_frame, text="Description")
    rule_description_text = tk.Text(rules_right_frame, width=25, height=4)
    rule_description_text_scrollbar = tk.Scrollbar(rules_right_frame, orient="vertical", command=rule_description_text.yview)
    rule_description_text.configure(yscrollcommand=rule_description_text_scrollbar.set)
    rule_description_text.bind("<FocusOut>", lambda event: save_rule())

    rule_platforms_label = tk.Label(rules_right_frame, text="Plataforms")
    rule_platforms_listbox = tk.Listbox(rules_right_frame, selectmode="single", width=25, height=3)
    rule_platforms_listbox.bind('<<ListboxSelect>>', lambda event:edit_rule_platform())
    rule_platforms_listbox_scrollbar = tk.Scrollbar(rules_right_frame, orient="vertical", command=rule_platforms_listbox.yview)
    rule_platforms_listbox.configure(yscrollcommand=rule_platforms_listbox_scrollbar.set)

    rule_sources_label = tk.Label(rules_right_frame, text="Sources")
    rule_sources_listbox = tk.Listbox(rules_right_frame, selectmode="single", width=25, height=3)
    rule_sources_listbox.bind('<<ListboxSelect>>', lambda event:edit_rule_source())
    rule_sources_listbox_scrollbar = tk.Scrollbar(rules_right_frame, orient="vertical", command=rule_sources_listbox.yview)
    rule_sources_listbox.configure(yscrollcommand=rule_sources_listbox_scrollbar.set)

    rule_language_label = tk.Label(rules_right_frame, text="Language")
    rule_language_entry = tk.Entry(rules_right_frame, width=25)
    rule_language_entry.bind("<FocusOut>", lambda event: save_rule())

    rule_query_label = tk.Label(rules_right_frame, text="Query")
    rule_query_text = tk.Text(rules_right_frame, width=35, height=4)
    rule_query_text_scrollbar = tk.Scrollbar(rules_right_frame, orient="vertical", command=rule_query_text.yview)
    rule_query_text.configure(yscrollcommand=rule_query_text_scrollbar.set)
    rule_query_text.bind("<FocusOut>", lambda event: save_rule())

    rule_coverage_techniques_label = tk.Label(rules_right_frame, text="Coverage\nTechniques", justify="left")
    rule_coverage_techniques_listbox = tk.Listbox(rules_right_frame, selectmode="single", width=25, height=3)
    rule_coverage_techniques_listbox.bind('<<ListboxSelect>>', lambda event:edit_rule_coverage_technique())
    rule_coverage_techniques_listbox_scrollbar = tk.Scrollbar(rules_right_frame, orient="vertical", command=rule_coverage_techniques_listbox.yview)
    rule_coverage_techniques_listbox.configure(yscrollcommand=rule_coverage_techniques_listbox_scrollbar.set)

    rule_reference_ttp_label = tk.Label(rules_right_frame, text="Reference TTP")
    rule_reference_ttp_entry = tk.Entry(rules_right_frame, width=25)
    rule_reference_ttp_entry.configure(state="readonly")

    rule_notes_label = tk.Label(rules_right_frame, text="Notes")
    rule_notes_listbox = tk.Listbox(rules_right_frame, selectmode="single", width=35, height=3)
    rule_notes_listbox.bind('<<ListboxSelect>>', lambda event:edit_rule_note())
    rule_notes_listbox_scrollbar = tk.Scrollbar(rules_right_frame, orient="vertical", command=rule_notes_listbox.yview)
    rule_notes_listbox.configure(yscrollcommand=rule_notes_listbox_scrollbar.set)

    #Botoes
    rule_description_edit_button = tk.Button(rules_right_frame, text=t("Editar >>"), command=edit_rule_description)
    rule_platform_add_button = tk.Button(rules_right_frame, text=t("Inserir >>"), command=add_rule_platform)
    rule_source_add_button = tk.Button(rules_right_frame, text=t("Inserir >>"), command=add_rule_source)
    rule_coverage_technique_add_button = tk.Button(rules_right_frame, text=t("Inserir >>"), command=add_rule_coverage_technique)
    rule_note_add_button = tk.Button(rules_right_frame, text=t("Inserir >>"), command=add_rule_note)
    rule_query_edit_button = tk.Button(rules_right_frame, text=t("Editar >>"), command=edit_rule_query)

    #rule_save_button = tk.Button(rules_right_frame, text="Salvar Regra", command=lambda: save_rule(verbose=True))
    rule_delete_button = tk.Button(rules_right_frame, text=t("Excluir Regra"), command=delete_rule)

    #Organização
    #Column0
    rule_id_label.grid(row=0, column=0, padx=5, sticky="w")
    rule_creation_date_label.grid(row=1, column=0, padx=5, sticky="w")
    rule_updated_date_label.grid(row=2, column=0, padx=5, sticky="w")
    rule_description_label.grid(row=3, column=0, padx=5, sticky="w")
    rule_description_edit_button.grid(row=4, column=0, padx=5, sticky="w")
    rule_platforms_label.grid(row=5, column=0, padx=5, sticky="w")
    rule_platform_add_button.grid(row=6, column=0, padx=5, sticky="w")
    rule_coverage_techniques_label.grid(row=7, column=0, padx=5, sticky="w")
    rule_coverage_technique_add_button.grid(row=8, column=0, padx=5, sticky="w")
    rule_delete_button.grid(row=9, column=0, columnspan=6, padx=10, pady=5) #Delete Button
    #Column1
    rule_id_entry.grid(row=0, column=1, columnspan=2, padx=5, sticky="ew")
    rule_creation_date_entry.grid(row=1, column=1, columnspan=2, padx=5, sticky="ew")
    rule_update_date_entry.grid(row=2, column=1, columnspan=2, padx=5, sticky="ew")
    rule_description_text.grid(row=3, column=1, rowspan=2, padx=5, sticky="ew")
    rule_platforms_listbox.grid(row=5, column=1, rowspan=2, padx=(5, 0), sticky="ew")
    rule_coverage_techniques_listbox.grid(row=7, column=1, rowspan=2, padx=5, sticky="ew")
    rules_right_frame.columnconfigure(1, weight=1)
    #Column2
    rule_description_text_scrollbar.grid(row=3, column=2, rowspan=2, padx=(0, 5), sticky="ns")
    rule_platforms_listbox_scrollbar.grid(row=5, column=2, rowspan=2, padx=(0, 5), sticky="ns")
    rule_coverage_techniques_listbox_scrollbar.grid(row=7, column=2, rowspan=2, padx=(0, 5), sticky="ns")
    #Column3
    rule_reference_ttp_label.grid(row=0, column=3, padx=5, sticky="w")
    rule_language_label.grid(row=1, column=3, padx=5, sticky="w")
    rule_query_label.grid(row=2, column=3, padx=5, sticky="w")
    rule_query_edit_button.grid(row=3, column=3, padx=5, sticky="w")
    rule_sources_label.grid(row=5, column=3, padx=5, sticky="w")
    rule_source_add_button.grid(row=6, column=3, padx=5, sticky="w")
    rule_notes_label.grid(row=7, column=3, padx=5, sticky="w")
    rule_note_add_button.grid(row=8, column=3, padx=5, sticky="w")
    #rule_save_button.grid(row=9, column=3, columnspan=3, padx=10, pady=5, sticky="w") #Save Button
    #Column4
    rule_reference_ttp_entry.grid(row=0, column=4, columnspan=2, padx=5, sticky="ew")
    rule_language_entry.grid(row=1, column=4, columnspan=2, padx=5, sticky="ew")
    rule_query_text.grid(row=2, column=4, rowspan=3, padx=(5, 0), sticky="nsew")
    rule_sources_listbox.grid(row=5, column=4, rowspan=2, padx=(5, 0), sticky="ew")
    rule_notes_listbox.grid(row=7, column=4, rowspan=2, padx=(5, 0), sticky="ew")
    rules_right_frame.columnconfigure(4, weight=1)
    #Column5
    rule_query_text_scrollbar.grid(row=2, column=5, rowspan=3, padx=(0, 5), sticky="ns")
    rule_sources_listbox_scrollbar.grid(row=5, column=5, rowspan=2, padx=(0, 5), sticky="ns")
    rule_notes_listbox_scrollbar.grid(row=7, column=5, rowspan=2, padx=(0, 5), sticky="ns")


    #### Funções de botão de stage3_frame ####

    def add_validation_note():
        #Pega id da TTP selecionada
        selected_ttp_id = ttp_id_entry.get()
        if not selected_ttp_id:
            #Não tem TTP selecionada
            messagebox.showerror("Erro", "Selecione ou crie uma TTP.")
            return
        # Pega objeto da TTP selecionada
        selected_ttp = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
        if not selected_ttp:
            print("Erro: selected_ttp == None")
            return
        #Pega id da Rule selecionada
        selected_rule_id = rule_id_entry.get()
        if not selected_rule_id:
            messagebox.showerror("Erro", "Selecione uma Detection Rule.")
            return
        #Pega objeto da Rule selecionada
        idx = _threat.ttps.index(selected_ttp) #Índice da TTP selecionada
        selected_rule = next((rule for rule in _threat.ttps[idx].detection_rules if rule.rule_id == selected_rule_id), None)
        if not selected_rule:
            print("Erro: selected_rule == None")
            return

        #Função para adicionar nova validation_note          
        def add(event=None):
            new_validation_note = validation_notes_text.get("1.0", tk.END).rstrip("\n").strip()
            if not new_validation_note:
                messagebox.showerror("Erro", "O campo está vazio.")
                return
            # Atualiza dados da Rule selecionada no objeto _threat
            idx_rule = _threat.ttps[idx].detection_rules.index(selected_rule)
            validation = _threat.ttps[idx].detection_rules[idx_rule].validation
            if validation is None:
                validation = Validation(VALIDATION_STATUS_LIST[0], "", "", [], [])
                _threat.ttps[idx].detection_rules[idx_rule].validation = validation
            _threat.ttps[idx].detection_rules[idx_rule].validation.notes.append(new_validation_note)
            # Atualiza listbox (se ainda selecionada a mesma rule)
            if selected_rule_id == rule_id_entry.get():
                validation_notes_listbox.insert(tk.END, new_validation_note)
            add_window.destroy()

        #Cria janela para adicionar nova validation_note
        add_window = tk.Toplevel(root)
        add_window.geometry(f"450x150+{root.winfo_x()+100}+{root.winfo_y()+100}")
        add_window.title("Incluir Nota de Validação na Regra " + selected_rule_id)

        content_frame = tk.Frame(add_window)
        content_frame.pack(fill="both", expand=True, padx=5, pady=5)
        tk.Label(content_frame, text="Nota").pack(side="left", padx=10)
        validation_notes_text = tk.Text(content_frame, height=5)
        validation_notes_text.pack(side="left", padx=10, fill="both", expand=True)
        validation_notes_text.bind("<Control-Return>", add)
        validation_notes_text.focus_set()
        
        action_frame = tk.Frame(add_window)
        action_frame.pack(side="bottom", padx=5, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=add_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Incluir", command=add).grid(row=0, column=1, padx=10, sticky="w")


    def edit_validation_note():
        #Pega id da TTP selecionada
        selected_ttp_id = ttp_id_entry.get()
        if not selected_ttp_id:
            #Não tem TTP selecionada
            messagebox.showerror("Erro", "Selecione ou crie uma TTP.")
            return
        # Pega objeto da TTP selecionada
        selected_ttp = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
        if not selected_ttp:
            print("Erro: selected_ttp == None")
            return
        #Pega id da Rule selecionada
        selected_rule_id = rule_id_entry.get()
        if not selected_rule_id:
            messagebox.showerror("Erro", "Selecione uma Detection Rule.")
            return
        #Pega objeto da Rule selecionada
        idx = _threat.ttps.index(selected_ttp) #Índice da TTP selecionada
        selected_rule = next((rule for rule in _threat.ttps[idx].detection_rules if rule.rule_id == selected_rule_id), None)
        if not selected_rule:
            print("Erro: selected_rule == None")
            return

        #Pega nota de Validação da Rule selecionada
        selected_index_listbox = validation_notes_listbox.curselection()
        if not selected_index_listbox:
            return
        selected_validation_note = validation_notes_listbox.get(selected_index_listbox)
        
        #Função para salvar nota de Validação
        def save(event=None):
            new_validation_note = validation_notes_text.get("1.0", tk.END).rstrip("\n").strip()
            if not new_validation_note:
                messagebox.showerror("Erro", "O campo está vazio.")
                return
            # Atualiza dados da Rule selecionada no objeto _threat
            idx_rule = _threat.ttps[idx].detection_rules.index(selected_rule)
            idx_note = _threat.ttps[idx].detection_rules[idx_rule].validation.notes.index(selected_validation_note)
            _threat.ttps[idx].detection_rules[idx_rule].validation.notes[idx_note] = new_validation_note
            # Atualiza listbox (se ainda selecionada a mesma rule)
            if selected_rule_id == rule_id_entry.get():
                validation_notes_listbox.delete(selected_index_listbox)
                validation_notes_listbox.insert(selected_index_listbox, new_validation_note)
            edit_window.destroy()

        #Função para excluir nota de Validação
        def delete():
            if messagebox.askyesno("Excluir", "Deseja excluir esta nota de Validação da Regra?"):
                # Atualiza dados da Rule selecionada no objeto _threat
                idx_rule = _threat.ttps[idx].detection_rules.index(selected_rule)
                _threat.ttps[idx].detection_rules[idx_rule].validation.notes.remove(selected_validation_note)
                # Atualiza listbox (se ainda selecionada a mesma rule)
                if selected_rule_id == rule_id_entry.get():
                    validation_notes_listbox.delete(selected_index_listbox)
                edit_window.destroy()

        #Cria janela para editar nota de Validação
        edit_window = tk.Toplevel(root)
        edit_window.geometry(f"450x150+{root.winfo_x()+100}+{root.winfo_y()+100}")
        edit_window.title("Editar Nota de Validação da Regra " + selected_rule_id)

        content_frame = tk.Frame(edit_window)
        content_frame.pack(fill="both", expand=True, padx=5, pady=5)
        tk.Label(content_frame, text="Nota").pack(side="left", padx=10)
        validation_notes_text = tk.Text(content_frame, height=5)
        validation_notes_text.insert("1.0", selected_validation_note)
        validation_notes_text.pack(side="left", padx=10, fill="both", expand=True)
        validation_notes_text.bind("<Control-Return>", save)
        validation_notes_text.focus_set()
        
        action_frame = tk.Frame(edit_window)
        action_frame.pack(side="bottom", padx=20, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=edit_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Salvar", command=save).grid(row=0, column=1, padx=10, sticky="w")
        tk.Button(action_frame, text="Excluir", command=delete).grid(row=0, column=2, padx=10, sticky="w")

    def select_validation_reference():
        #Pega id da TTP selecionada
        selected_ttp_id = ttp_id_entry.get()
        if not selected_ttp_id:
            #Não tem TTP selecionada
            messagebox.showerror("Erro", "Selecione ou crie uma TTP.")
            return
        # Pega objeto da TTP selecionada
        selected_ttp = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
        if not selected_ttp:
            print("Erro: selected_ttp == None")
            return
        #Pega id da Rule selecionada
        selected_rule_id = rule_id_entry.get()
        if not selected_rule_id:
            messagebox.showerror("Erro", "Selecione uma Detection Rule.")
            return
        #Pega objeto da Rule selecionada
        idx = _threat.ttps.index(selected_ttp) #Índice da TTP selecionada
        selected_rule = next((rule for rule in _threat.ttps[idx].detection_rules if rule.rule_id == selected_rule_id), None)
        if not selected_rule:
            print("Erro: selected_rule == None")
            return
        #Verifica se há referencias para serem adicionadas
        if not _threat.references:
            messagebox.showerror("Erro", "Não há referências para adicionar.")
            return
        
        def on_select_ref_id(event=None):
            print_selected_ref_listbox(ref_ids_listbox, _threat, selected_ref_text)
        
        def add(event=None):
            selected_ref_id = ref_ids_listbox.get(ref_ids_listbox.curselection()) if ref_ids_listbox.curselection() else None
            if selected_ref_id:
                #Verifica se já existe, para não incluir duplicata
                if selected_ref_id in selected_rule.validation.references:
                    messagebox.showerror("Erro", "Esta referência já existe na Validação.")
                    select_window.lift()
                    return
                # Atualiza o objeto _threat
                idx_rule = _threat.ttps[idx].detection_rules.index(selected_rule)
                validation = _threat.ttps[idx].detection_rules[idx_rule].validation
                if validation is None:
                    validation = Validation(VALIDATION_STATUS_LIST[0], "", "", [], [])
                    _threat.ttps[idx].detection_rules[idx_rule].validation = validation
                _threat.ttps[idx].detection_rules[idx_rule].validation.references.append(selected_ref_id)
                # Atualiza listbox (se ainda selecionada a mesma rule)
                if selected_rule_id == rule_id_entry.get():
                    validation_references_listbox.insert(tk.END, selected_ref_id)
                select_window.destroy()
            else:
                messagebox.showerror("Erro", "Selecione uma Referência.")
                select_window.lift()

        #Cria janela
        select_window = tk.Toplevel(root)
        select_window.title("Selecionar Referência para a Validação da Regra" + selected_rule_id)
        select_window.geometry(f"500x300+{root.winfo_x()+100}+{root.winfo_y()+100}")
        #Content Frame
        content_frame = tk.Frame(select_window)
        content_frame.pack(fill="both", expand=True, padx=5, pady=5)
        #Column0
        tk.Label(content_frame, text="Referências").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        ref_ids_listbox = tk.Listbox(content_frame, width=25, height=5, selectmode="single")
        ref_ids_listbox.grid(row=1, column=0, padx=5, sticky="wns")
        ref_ids_listbox.bind("<<ListboxSelect>>", on_select_ref_id)
        #Povoa listbox
        for ref in _threat.references:
            ref_ids_listbox.insert(tk.END, ref.ref_id)
        ref_ids_listbox.focus_set()
        ref_ids_listbox.bind("<Return>", add)
        #Column1
        tk.Label(content_frame, text="Dados da Referência").grid(row=0, column=1, padx=5, pady=5, sticky="w")
        selected_ref_text = tk.Text(content_frame, width=40, height=5, state="disabled")
        selected_ref_text.grid(row=1, column=1, padx=(5,0), pady=5, sticky="news")
        content_frame.columnconfigure(1, weight=1)
        #Column2
        vscrollbar = tk.Scrollbar(content_frame, orient="vertical", command=selected_ref_text.yview)
        vscrollbar.grid(row=1, column=2, padx=(0,5), sticky="ns")
        selected_ref_text.configure(yscrollcommand=vscrollbar.set)

        content_frame.rowconfigure(1, weight=1)
        #Action Frame
        action_frame = tk.Frame(select_window)
        action_frame.pack(side="bottom", padx=20, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=select_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Incluir", command=add).grid(row=0, column=1, padx=10, sticky="w")
        #Seleciona primeiro item da listbox
        if ref_ids_listbox.size() > 0:
            ref_ids_listbox.select_set(0) 
            on_select_ref_id()


    def edit_exclude_validation_reference():
        #Pega id da TTP selecionada
        selected_ttp_id = ttp_id_entry.get()
        if not selected_ttp_id:
            #Não tem TTP selecionada
            messagebox.showerror("Erro", "Selecione ou crie uma TTP.")
            return
        # Pega objeto da TTP selecionada
        selected_ttp = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
        if not selected_ttp:
            print("Erro: selected_ttp == None")
            return
        #Pega id da Rule selecionada
        selected_rule_id = rule_id_entry.get()
        if not selected_rule_id:
            messagebox.showerror("Erro", "Selecione uma Detection Rule.")
            return
        #Pega objeto da Rule selecionada
        idx = _threat.ttps.index(selected_ttp) #Índice da TTP selecionada
        selected_rule = next((rule for rule in _threat.ttps[idx].detection_rules if rule.rule_id == selected_rule_id), None)
        if not selected_rule:
            print("Erro: selected_rule == None")
            return
        
        #Pega referência da Validação da Rule selecionada
        selected_index_listbox = validation_references_listbox.curselection()
        if not selected_index_listbox:
            return
        initial_ref_validation = validation_references_listbox.get(selected_index_listbox)

        def on_select_ref_id(event=None):
            print_selected_ref_listbox(ref_ids_listbox, _threat, selected_ref_text)
        
        def save(event=None):
            selected_ref_id = ref_ids_listbox.get(ref_ids_listbox.curselection()) if ref_ids_listbox.curselection() else None
            if selected_ref_id:
                if selected_ref_id == initial_ref_validation: #É a mesma referencia, logo não precisa atualizar
                    select_window.destroy()
                    return
                # Atualiza dados da Rule selecionada no objeto _threat
                idx_rule = _threat.ttps[idx].detection_rules.index(selected_rule)
                idx_ref = _threat.ttps[idx].detection_rules[idx_rule].validation.references.index(initial_ref_validation)
                _threat.ttps[idx].detection_rules[idx_rule].validation.references[idx_ref] = selected_ref_id
                # Atualiza listbox (se ainda selecionada a mesma rule)
                if selected_rule_id == rule_id_entry.get():
                    validation_references_listbox.delete(selected_index_listbox)
                    validation_references_listbox.insert(selected_index_listbox, selected_ref_id)
                select_window.destroy()
            else:
                messagebox.showerror("Erro", "Selecione uma Referência.")
                select_window.lift()

        def delete():
            if messagebox.askyesno("Excluir", "Deseja excluir a referêrncia " + initial_ref_validation + " da Validação?"):
                # Atualiza dados da Rule selecionada no objeto _threat
                idx_rule = _threat.ttps[idx].detection_rules.index(selected_rule)
                _threat.ttps[idx].detection_rules[idx_rule].validation.references.remove(initial_ref_validation)
                # Atualiza listbox (se ainda selecionada a mesma rule)
                if selected_rule_id == rule_id_entry.get():
                    validation_references_listbox.delete(selected_index_listbox)
                select_window.destroy()
            else:
                select_window.lift()

        #Cria janela
        select_window = tk.Toplevel(root)
        select_window.title("Editar/Excluir Referência da Validação da Regra " + selected_rule_id)
        select_window.geometry(f"500x300+{root.winfo_x()+100}+{root.winfo_y()+100}")
        #Content Frame
        content_frame = tk.Frame(select_window)
        content_frame.pack(fill="both", expand=True, padx=5, pady=5)
        #Column0
        tk.Label(content_frame, text="Ref. ID selecionada:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        tk.Label(content_frame, text="Referências").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        ref_ids_listbox = tk.Listbox(content_frame, width=25, height=5, selectmode="single")
        ref_ids_listbox.grid(row=2, column=0, padx=5, sticky="wns")
        ref_ids_listbox.bind("<<ListboxSelect>>", on_select_ref_id)
        #Povoa listbox
        for ref in _threat.references:
            ref_ids_listbox.insert(tk.END, ref.ref_id)
        ref_ids_listbox.focus_set()
        ref_ids_listbox.bind("<Return>", save)
        #Column1
        initial_ref_id_entry = tk.Entry(content_frame, width=25)
        initial_ref_id_entry.insert(0, initial_ref_validation)
        initial_ref_id_entry.configure(state="readonly")
        initial_ref_id_entry.grid(row=0, column=1, columnspan=2, padx=5, pady=5, sticky="w")
        tk.Label(content_frame, text="Dados da Referência").grid(row=1, column=1, padx=5, pady=5, sticky="w")
        selected_ref_text = tk.Text(content_frame, width=40, height=5, state="disabled")
        selected_ref_text.grid(row=2, column=1, columnspan=2, padx=(5,0), sticky="news")
        content_frame.columnconfigure(1, weight=1)
        #Column2
        tk.Button(content_frame, text="Excluir", command=delete).grid(row=0, column=2, padx=5, sticky="w")
        #Column3
        vscrollbar = tk.Scrollbar(content_frame, orient="vertical", command=selected_ref_text.yview)
        vscrollbar.grid(row=2, column=3, padx=(0,5), sticky="ns")
        selected_ref_text.configure(yscrollcommand=vscrollbar.set)
        
        content_frame.rowconfigure(2, weight=1)
        #Action Frame
        action_frame = tk.Frame(select_window)
        action_frame.pack(side="bottom", padx=20, pady=(5,10))
        tk.Button(action_frame, text="Cancelar", command=select_window.destroy).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(action_frame, text="Salvar", command=save).grid(row=0, column=1, padx=10, sticky="w")
        #Seleciona na listbox o mesmo id que foi selecionado no listbox do app
        for i, ref_id in enumerate(ref_ids_listbox.get(0, tk.END)):
            if ref_id == initial_ref_validation:
                ref_ids_listbox.select_set(i)
                on_select_ref_id()
                break


    def clear_validation_fields():
        validation_status_combobox.set("")
        validation_update_date_entry.configure(state="normal")
        validation_update_date_entry.delete(0, tk.END)
        validation_update_date_entry.configure(state="readonly")
        validation_dataset_entry.delete(0, tk.END)
        validation_references_listbox.delete(0, tk.END)
        validation_notes_listbox.delete(0, tk.END)

    def save_validation(verbose: bool = False):
        #Pega id da Rule selecionada
        selected_rule_id = rule_id_entry.get()
        if not selected_rule_id:
            if verbose: 
                messagebox.showerror("Erro", "Selecione uma Detection Rule.")
            return
        #Pega id da TTP selecionada
        selected_ttp_id = ttp_id_entry.get()
        if not selected_ttp_id:
            #Não tem TTP selecionada
            if verbose: 
                messagebox.showerror("Erro", "Selecione ou crie uma TTP.")
            return
        # Pega objeto da TTP selecionada
        selected_ttp = next((ttp for ttp in _threat.ttps if ttp.ttp_id == selected_ttp_id), None)
        if not selected_ttp:
            print("Erro: selected_ttp == None")
            return
        #Pega objeto da Rule selecionada
        idx = _threat.ttps.index(selected_ttp) #Índice da TTP selecionada
        selected_rule = next((rule for rule in _threat.ttps[idx].detection_rules if rule.rule_id == selected_rule_id), None)
        if not selected_rule:
            print("Erro: selected_rule == None")
            return
        idx_rule = _threat.ttps[idx].detection_rules.index(selected_rule)
        #Atualiza validation_update_date
        validation_update_date_entry.configure(state="normal")
        validation_update_date_entry.delete(0, tk.END)
        validation_update_date_entry.insert(0, get_today_date())
        validation_update_date_entry.configure(state="readonly")
        #Atualiza os campos do objeto da Rule
        _threat.ttps[idx].detection_rules[idx_rule].validation = Validation(
            status=validation_status_combobox.get(),
            update_date=validation_update_date_entry.get(),
            dataset=validation_dataset_entry.get(),
            references=list(validation_references_listbox.get(0, tk.END)),
            notes=list(validation_notes_listbox.get(0, tk.END))
        )
        if verbose: 
            messagebox.showinfo("Sucesso", "Dados de validação atualizados na Regra " + selected_rule_id)
    
    def new_validation():
        rule_id = rule_id_entry.get()
        if not rule_id:
            messagebox.showerror("Erro", "Selecione uma Detection Rule.")
            return
        if messagebox.askokcancel("Resetar Validação", "Deseja resetar os dados de validação da Regra " + rule_id + "?"):
            clear_validation_fields()
            #Muda status para "unchecked"
            validation_status_combobox.set(VALIDATION_STATUS_LIST[0])
            save_validation()

    def validate_rule():
        if not rule_id_entry.get():
            messagebox.showerror("Erro", "Selecione uma Detection Rule.")
            return
        #Muda status para "validated"
        validation_status_combobox.set(VALIDATION_STATUS_LIST[1])
        #Salvar no objeto _threat
        save_validation(verbose=True)

    #### Estrutura do stage3_frame ####

    ## Widgets do stage3_frame
    #Campos
    validation_detectionrule_id_label = tk.Label(stage3_frame, text="Selected Rule")
    validation_detectionrule_id_entry = tk.Entry(stage3_frame, width=35)
    validation_detectionrule_id_entry.configure(state="readonly")

    validation_status_label = tk.Label(stage3_frame, text="Status")
    validation_status_combobox = ttk.Combobox(stage3_frame, state="readonly", values=VALIDATION_STATUS_LIST, width=35)
    validation_status_combobox.bind("<<ComboboxSelected>>", lambda event: save_validation())
    
    validation_update_date_label = tk.Label(stage3_frame, text="Update Date")
    validation_update_date_entry = tk.Entry(stage3_frame, width=35)
    validation_update_date_entry.configure(state="readonly")

    validation_dataset_label = tk.Label(stage3_frame, text="Dataset")
    validation_dataset_entry = tk.Entry(stage3_frame, width=35)
    validation_dataset_entry.bind("<FocusOut>", lambda event: save_validation())

    validation_references_label = tk.Label(stage3_frame, text="References")
    validation_references_listbox = tk.Listbox(stage3_frame, selectmode="single", width=35, height=3)
    validation_references_listbox.bind("<<ListboxSelect>>", lambda event: edit_exclude_validation_reference())
    validation_references_listbox_scrollbar = tk.Scrollbar(stage3_frame, orient="vertical", command=validation_references_listbox.yview)
    validation_references_listbox.configure(yscrollcommand=validation_references_listbox_scrollbar.set)
    
    validation_notes_label = tk.Label(stage3_frame, text="Notes")
    validation_notes_listbox = tk.Listbox(stage3_frame, selectmode="single", width=35, height=3)
    validation_notes_listbox.bind("<<ListboxSelect>>", lambda event: edit_validation_note())
    validation_notes_listbox_scrollbar = tk.Scrollbar(stage3_frame, orient="vertical", command=validation_notes_listbox.yview)
    validation_notes_listbox.configure(yscrollcommand=validation_notes_listbox_scrollbar.set)

    #Botoes
    validation_reference_add_button = tk.Button(stage3_frame, text=t("Inserir >>"), command=select_validation_reference)
    validation_note_add_button = tk.Button(stage3_frame, text=t("Inserir >>"), command=add_validation_note)
    #validation_save_button = tk.Button(stage3_frame, text="Salvar", command=lambda: save_validation(verbose=True))
    validation_validate_button = tk.Button(stage3_frame, text=t("Validar"), command=validate_rule)
    new_validation_button = tk.Button(stage3_frame, text=t("Resetar"), command=new_validation)

    #Organização
    #Column0
    validation_detectionrule_id_label.grid(row=0, column=0, padx=5, sticky="w")
    validation_update_date_label.grid(row=1, column=0, padx=5, sticky="w")
    validation_references_label.grid(row=2, column=0, padx=5, sticky="w")
    validation_reference_add_button.grid(row=3, column=0, padx=5, sticky="w")
    validation_validate_button.grid(row=4, column=0, columnspan=3, padx=10, pady=5, sticky="e") #Validate button
    #Column1
    validation_detectionrule_id_entry.grid(row=0, column=1, columnspan=2, padx=5, sticky="ew")
    validation_update_date_entry.grid(row=1, column=1, columnspan=2, padx=5, sticky="ew")
    validation_references_listbox.grid(row=2, column=1, rowspan=2, padx=(5,0), sticky="nsew")
    stage3_frame.columnconfigure(1, weight=1)
    #Column2
    validation_references_listbox_scrollbar.grid(row=2, column=2, rowspan=2, padx=(0,5), sticky="ns")
    #Column3
    validation_status_label.grid(row=0, column=3, padx=5, sticky="w")
    validation_dataset_label.grid(row=1, column=3, padx=5, sticky="w")
    validation_notes_label.grid(row=2, column=3, padx=5, sticky="w")
    validation_note_add_button.grid(row=3, column=3, padx=5, sticky="w")
    #validation_save_button.grid(row=6, column=3, columnspan=3, padx=10, pady=5, sticky="w") #Save button
    new_validation_button.grid(row=4, column=3, columnspan=3, padx=10, pady=5, sticky="w") #Reset button
    #Column4
    validation_status_combobox.grid(row=0, column=4, columnspan=2, padx=5, sticky="ew")
    validation_dataset_entry.grid(row=1, column=4, columnspan=2, padx=5, sticky="ew")
    validation_notes_listbox.grid(row=2, column=4, rowspan=2, padx=(5,0), sticky="nsew")
    stage3_frame.columnconfigure(4, weight=1)
    #Column5
    validation_notes_listbox_scrollbar.grid(row=2, column=5, rowspan=2, padx=(0,5), sticky="ns")
    
    #### Funções de botão do stage4_frame ####

    def preview_runbook():
        def print_runbook_text_area(threat: Threat):
            text_area.configure(state="normal")
            text_area.delete(1.0, tk.END)
            text_area.insert(tk.INSERT, generate_runbook(_threat))
            text_area.configure(state="disabled")

        view_window = tk.Toplevel(root)
        view_window.transient(root) # Faz com que a janela seja filha da janela principal
        view_window.title("Previsualizar Runbook")
        view_window.geometry(f"600x600+{root.winfo_x()+100}+{root.winfo_y()+100}")

        # Cria a text area
        text_frame = tk.Frame(view_window)
        text_frame.pack(fill="both", expand=True, padx=10, pady=5)
        text_area = tk.Text(text_frame, wrap=tk.WORD, width=20, height=5)
        text_area.pack(side="left", fill="both", expand=True)
        text_area.configure(state="disabled")

        # Cria a barra de rolagem vertical
        vscrollbar = tk.Scrollbar(text_frame, orient="vertical", command=text_area.yview)
        vscrollbar.pack(side="right", fill="y")
        text_area.configure(yscrollcommand=vscrollbar.set)

        # Cria os botões
        button_frame = tk.Frame(view_window)
        button_frame.pack(side="bottom", padx=10, pady=(5,10))
        tk.Button(button_frame, text="Refresh", command=lambda: print_runbook_text_area(_threat)).grid(row=0, column=0, padx=10, sticky="e")
        tk.Button(button_frame, text="Fechar", command=view_window.destroy).grid(row=0, column=1, padx=10, sticky="w")

        #Salvar campos
        save_threat_fields()
        #Imprime o runbook
        print_runbook_text_area(_threat)

    #### Estrutura do stage4_frame ####
    
    tk.Label(stage4_frame, text=t("Geração do Runbook")).pack(side="top", padx=5, pady=5, anchor="w")

    #Botões
    runbook_preview_button = tk.Button(stage4_frame, text="Runbook Preview", command=preview_runbook)
    runbook_preview_button.pack(padx=5, pady=5,side="left")
    runbook_save_button = tk.Button(stage4_frame, text=t("Gerar arquivo YAML"), command=save_runbook)
    runbook_save_button.pack(padx=5, pady=5,side="left")

    
    #### Funções do App ####
       
    def clear_all_fields():
        """
        Apaga os dados de todos os campos da interface gráfica.
        """
        #Limpa os campos principais da threat
        threat_id_entry.configure(state="normal")
        threat_id_entry.delete(0, tk.END)
        threat_id_entry.configure(state="readonly")
        title_entry.delete(0, tk.END)
        creation_date_entry.configure(state="normal")
        creation_date_entry.delete(0, tk.END)
        creation_date_entry.configure(state="readonly")
        update_date_entry.configure(state="normal")
        update_date_entry.delete(0, tk.END)
        update_date_entry.configure(state="readonly")
        type_entry.delete(0, tk.END)
        domain_combobox.delete(0, tk.END)
        platforms_listbox.delete(0, tk.END)
        description_text.delete(1.0, tk.END)
        related_threats_listbox.delete(0, tk.END)
        notes_listbox.delete(0, tk.END)
        references_listbox.delete(0, tk.END)
        ttps_listbox.delete(0, tk.END)
        rules_listbox.delete(0, tk.END)
        #Limpa outros campos
        clear_reference_fields() #Limpa os campos da referencia
        clear_ttp_fields() #Limpa os campos da ttp
        clear_rule_fields() #Limpa os campos da rule (inclui os da validação)

    def load_threat_data():
        """
        Insere os dados do objeto _threat nos respectivos campos da interface gráfica.
        """
        # Limpando os campos
        clear_all_fields()
        # Inserindo nos campos
        threat_id_entry.configure(state="normal")
        threat_id_entry.insert(0, _threat.threat_id)
        threat_id_entry.configure(state="readonly")
        title_entry.insert(0, _threat.title)
        creation_date_entry.configure(state="normal")
        creation_date_entry.insert(0, _threat.creation_date)
        creation_date_entry.configure(state="readonly")
        update_date_entry.configure(state="normal")
        update_date_entry.insert(0, _threat.update_date)
        update_date_entry.configure(state="readonly")
        type_entry.insert(0, _threat.type)
        domain_combobox.insert(0, _threat.domain)
        platforms_listbox.insert(0, *_threat.platforms)
        description_text.insert(tk.INSERT, _threat.description)
        related_threats_listbox.insert(0, *_threat.related_threats)
        notes_listbox.insert(0, *_threat.notes)
        for ref in _threat.references:
            references_listbox.insert(tk.END, ref.ref_id)
        for ttp in _threat.ttps:
            ttps_listbox.insert(tk.END, ttp.ttp_id)

    
    
    def on_resize_app(event):
        canvas_root.config(scrollregion=canvas_root.bbox("all"))
    
    def on_mousewheel(event):
        canvas_root.yview_scroll(-1 * int(event.delta/120), "units")


    # Ajusta a região de rolagem do canvas
    canvas_root.update_idletasks()
    canvas_root.config(scrollregion=canvas_root.bbox("all"))
    root.bind("<Configure>", on_resize_app) #reajusta ao redimensionar a janela
    root.bind("<MouseWheel>", on_mousewheel)
    # Main Loop
    root.mainloop()
    ################################################### 


########################
#        MAIN          #
########################

if __name__ == "__main__":
    app()