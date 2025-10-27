import time
import yaml
from classes import (  # Assuming classes.py is in the same directory
    Reference, Validation, DetectionRule, TTP, Threat
)
import tkinter as tk
from mitre_utils import get_tactic_name, get_technique_name

# Prerequisites
# pip install pyyaml

######################################
# Variáveis globais
######################################
global _locale
_locale = "pt-BR"

######################################
# Funções de utilidade
######################################

def join_lines(text_area: tk.Text):
    old_text = text_area.get("1.0", tk.END).rstrip("\n").strip()
    new_text = old_text.replace('\n', ' ')
    text_area.delete("1.0", tk.END)
    text_area.insert(tk.INSERT, new_text)

def separate_phrases(text_area: tk.Text):
    old_text = text_area.get("1.0", tk.END).rstrip("\n").strip()
    new_text = old_text.replace('. ', '. \n')
    text_area.delete("1.0", tk.END)
    text_area.insert(tk.INSERT, new_text)


def generate_key(prefix: str, increment=False) -> str:
    """
    Função geradora de chaves

    Args:
        prefix (str): Prefixos esperados "THR", "REF", "TTP", "DTR"

    Returns:
        str: Retorna a chave gerada. Exemplo THR-0017-1241-4589
    """
    # Get the current Unix timestamp (seconds since epoch)
    timestamp = int(time.time())
    if increment:
        timestamp += 1

    # Convert the timestamp to an 12-digit string
    timestamp_str = str(timestamp).zfill(12)
    #print(timestamp_str)

    # Generate the key in the format THR-abcd-efgh-ijkl
    key = f"{prefix}-{timestamp_str[:4]}-{timestamp_str[4:8]}-{timestamp_str[8:]}"

    return key


def get_today_date() -> str:
    return time.strftime("%Y-%m-%d")

#########################################
# Funções de interface
#########################################


def mudar_selecao_listbox(listbox: tk.Listbox, event: tk.Event):
        # Obtém o índice do item atualmente selecionado
        index = listbox.curselection()[0]
        # Calcula o novo índice com base na seta pressionada
        if event.keysym == 'Up':
            novo_indice = index - 1
        elif event.keysym == 'Down':
            novo_indice = index + 1
        # Verifica se o novo índice está dentro dos limites da listbox
        if 0 <= novo_indice < listbox.size():
            listbox.selection_clear(0, tk.END)  # Limpa todas as seleções
            listbox.activate(novo_indice)  # Ativa o novo item
            listbox.selection_set(novo_indice)  # Seleciona o novo item
            listbox.event_generate("<<ListboxSelect>>")  # Aciona o evento <<ListboxSelect>>

#########################################
# Funções de Carregar Runbook
#########################################

def load_runbook_from_file(file_path):
    """
    Populates instances of Threat and related classes from a YAML file.

    Args:
        file_path (str): Path to the YAML file.

    Returns:
        Threat: An instance of the Threat class populated from the YAML data.

    Raises:
        FileNotFoundError: If the file is not found.
        yaml.YAMLError: If there's an error parsing the YAML.
        ValueError: If required fields are missing or data types are invalid.
    """

    try:
        with open(file_path, 'r', encoding='utf-8') as stream:
            threat_data = yaml.safe_load(stream)
    except FileNotFoundError:
        raise FileNotFoundError(f"Arquivo não encontrado: {file_path}")
    except yaml.YAMLError as exc:
        raise yaml.YAMLError(f"Erro ao carregar o arquivo YAML: {exc}")

    # Basic data validation
    # required_fields = [
    #     'title', 'threat_id', 'creation_date', 'update_date', 'type', 'domain',
    #     'platforms', 'description', 'references', 'TTPs'
    # ]
    # for field in required_fields:
    #     if field not in threat_data:
    #         raise ValueError(f"Campo obrigatório '{field}' não encontrado no YAML.")

    # Extract threat data
    threat = Threat(
        title=threat_data.get('title', ''), # Valor padrão: string vazia
        threat_id=threat_data.get('threat_id', ''),
        creation_date=threat_data.get('creation_date', ''),
        update_date=threat_data.get('update_date', ''),
        type=threat_data.get('type', ''),
        domain=threat_data.get('domain', ''),
        platforms=threat_data.get('platforms', []), # Valor padrão: lista vazia
        description=threat_data.get('description', ''),
        references=[Reference(**ref) for ref in threat_data['references']],
        ttps=[populate_ttp(ttp_data) for ttp_data in threat_data['TTPs']],
        related_threats=threat_data.get('related_threats', []),  # Valor padrão: lista vazia
        notes=threat_data.get('notes', []),  # Valor padrão: lista vazia
    )

    #print_threat(threat) #Imprime os dados no console

    return threat


def populate_ttp(ttp_data):
    """
    Populates an instance of TTP and related classes from a dictionary.

    Args:
        ttp_data (dict): Dictionary containing TTP data.

    Returns:
        TTP: An instance of the TTP class populated from the dictionary.

    Raises:
        ValueError: If essential fields are missing or data types are invalid.
    """

    # required_ttp_fields = ['ttp_id', 'tactic', 'technique']
    # missing_fields = [field for field in required_ttp_fields if field not in ttp_data]
    # if missing_fields:
    #     raise ValueError(f"Campos obrigatórios do TTPs ausentes: {', '.join(missing_fields)}")

    # Verifica se 'detection_rules' existe em ttp_data, se não, atribui uma lista vazia
    if 'detection_rules' in ttp_data:
        # Chama a função populate_detection_rules para cada detection_rule em ttp_data['detection_rules']
        detection_rules = [populate_detection_rules(detection_rule_data) for detection_rule_data in ttp_data['detection_rules']]
    else:
        detection_rules = []

    return TTP(
        ttp_id=ttp_data.get('ttp_id', ''), # Valor padrão: string vazia
        tactic=ttp_data.get('tactic', ''), # Valor padrão: string vazia
        technique=ttp_data.get('technique', ''), # Valor padrão: string vazia
        procedure=ttp_data.get('procedure', ''), # Valor padrão: string vazia
        secondary_techniques=ttp_data.get('secondary_techniques', []), # Valor padrão: lista vazia
        related_ttps=ttp_data.get('related_ttps', []), # Valor padrão: lista vazia
        references=ttp_data.get('references', []), # Valor padrão: lista vazia
        notes=ttp_data.get('notes', []), # Valor padrão: lista vazia
        ttp_chain=ttp_data.get('ttp_chain', []), # Valor padrão: lista vazia
        detection_rules=detection_rules
    )

def populate_detection_rules(detection_rule_data):
    """
    Populates an instance of DetectionRule and related classes from a dictionary.

    Args:
        detection_rule_data (dict): Dictionary containing DetectionRule data.

    Returns:
        DetectionRule: An instance of the DetectionRule class populated from the dictionary.
    """
    # required_detection_rules_fields = ['rule_id', 'creation_date', 'platforms', 'sources', 'query','coverage_techniques']
    # missing_fields = [field for field in required_detection_rules_fields if field not in detection_rule_data]
    # if missing_fields:
    #     raise ValueError(f"Campos obrigatórios do detection_rules ausentes: {', '.join(missing_fields)}")
    
        # Verifica se 'validation' existe em detection_rule_data, se não, atribui uma lista vazia
    if 'validation' in detection_rule_data:
        validation = Validation(
            status=detection_rule_data['validation'].get('status', ''), # Valor padrão: string vazia
            update_date=detection_rule_data['validation'].get('update_date', ''),
            dataset=detection_rule_data['validation'].get('dataset', ''),
            references=detection_rule_data['validation'].get('references', []), # Valor padrão: lista vazia
            notes=detection_rule_data['validation'].get('notes', []), # Valor padrão: lista vazia
        )
    else:
        validation = []

    return DetectionRule(
        rule_id = detection_rule_data.get('rule_id', ''), # Valor padrão: string vazia
        creation_date = detection_rule_data.get('creation_date', ''), 
        update_date = detection_rule_data.get('update_date', ''),
        description = detection_rule_data.get('description', ''),
        platforms = detection_rule_data.get('platforms', []), # Valor padrão: lista vazia
        sources = detection_rule_data.get('sources', []),
        language = detection_rule_data.get('language', ''),
        query = detection_rule_data.get('query', ''),
        notes = detection_rule_data.get('notes', []),
        reference_ttp = detection_rule_data.get('reference_ttp', ''),
        coverage_techniques = detection_rule_data.get('covered_techniques', []),
        validation = validation
    )

############################
# Funções de Salvar Runbook
############################


def generate_runbook(threat: Threat):
    threat_data = {
        'title': threat.title,
        'threat_id': threat.threat_id,
        'creation_date': threat.creation_date,
        'update_date': threat.update_date,
        'type': threat.type,
        'domain': threat.domain,
        'platforms': threat.platforms,
        'description': threat.description,
        'references': [vars(ref) for ref in threat.references],
        'TTPs': [extract_ttp_data(ttp) for ttp in threat.ttps],
        'related_threats': threat.related_threats,
        'notes': threat.notes
    }
    return yaml.safe_dump(threat_data, allow_unicode=True, indent=2, sort_keys=False, default_flow_style=False)

def save_runbook_to_file(threat: Threat, file_path):
    """
    Saves the data from a Threat object to a YAML file.

    Args:
        threat (Threat): The Threat object containing the data to be saved.
        file_path (str): The path to the YAML file where the data will be saved.
    """

    threat_data = {
        'title': threat.title,
        'threat_id': threat.threat_id,
        'creation_date': threat.creation_date,
        'update_date': threat.update_date,
        'type': threat.type,
        'domain': threat.domain,
        'platforms': threat.platforms,
        'description': threat.description,
        'references': [vars(ref) for ref in threat.references],
        'TTPs': [extract_ttp_data(ttp) for ttp in threat.ttps],
        'related_threats': threat.related_threats,
        'notes': threat.notes
    }
    with open(file_path, 'w', encoding='utf-8') as file:
        #yaml.dump(threat_data, file, indent=2, allow_unicode=True, sort_keys=False)
        #yaml.dump(threat_data, file, indent=2, allow_unicode=True, sort_keys=False, default_flow_style=False)
        yaml.safe_dump(threat_data, file, indent=2, allow_unicode=True, sort_keys=False, default_flow_style=False)

def extract_ttp_data(ttp: TTP):
    """
    Extracts data from a TTP object and its related objects into a dictionary.

    Args:
        ttp (TTP): The TTP object.

    Returns:
        dict: A dictionary containing the extracted data.
    """
    ttp_data = {
        'ttp_id': ttp.ttp_id,
        'tactic': ttp.tactic,
        'technique': ttp.technique,
        'procedure': ttp.procedure,
        'secondary_techniques': ttp.secondary_techniques,
        'related_ttps': ttp.related_ttps,
        'references': ttp.references,
        'notes': ttp.notes,
        'ttp_chain': ttp.ttp_chain,
        'detection_rules': [extract_detection_rule_data(rule) for rule in ttp.detection_rules] if ttp.detection_rules else []
    }
    return ttp_data

def extract_detection_rule_data(rule: DetectionRule):
    """
    Extracts data from a DetectionRule object into a dictionary.

    Args:
        rule (DetectionRule): The DetectionRule object.

    Returns:
        dict: A dictionary containing the extracted data.
    """
    rule_data = {
        'rule_id': rule.rule_id,
        'creation_date': rule.creation_date,
        'update_date': rule.update_date,
        'description': rule.description,
        'platforms': rule.platforms,
        'sources': rule.sources,
        'language': rule.language,
        'query': rule.query,
        'covered_techniques': rule.coverage_techniques,
        'reference_ttp': rule.reference_ttp,
        'notes': rule.notes,
        'validation': vars(rule.validation) if rule.validation else None
    }
    return rule_data

#############################
# Funções de Print
#############################

def print_threat(threat: Threat):
    """
    Prints all data from a Threat object in the terminal.

    Args:
        threat (Threat): The Threat object.
    """
    print(f"Title: {threat.title}")
    print(f"Threat ID: {threat.threat_id}")
    print(f"Creation Date: {threat.creation_date}")
    print(f"Update Date: {threat.update_date}")
    print(f"Type: {threat.type}")
    print(f"Domain: {threat.domain}")
    print(f"Platforms: {'; '.join(threat.platforms)}")
    print(f"Description: {threat.description}")
    print(f"Related Threats: {'; '.join(threat.related_threats)}")
    print(f"Notes: {'; '.join(threat.notes)}")
    print("References:")
    for ref in threat.references:
        print(f"  - ID: {ref.ref_id}")
        print(f"     Type: {ref.type}")
        print(f"     Title: {ref.title}")
        print(f"     Authors: {'; '.join(ref.authors)}")
        print(f"     Date: {ref.date}")
        print(f"     Link: {ref.link}")
        print(f"     Notes: {'; '.join(ref.notes)}")
    print("TTPs:")
    for ttp in threat.ttps:
        print(f"  - TTP ID: {ttp.ttp_id}")
        print(f"     Tactic: {ttp.tactic}")
        print(f"     Technique: {ttp.technique}")
        print(f"     Procedure: {ttp.procedure}")
        print(f"     Secondary Techniques: {'; '.join(ttp.secondary_techniques)}")
        print(f"     Related TTPs: {'; '.join(ttp.related_ttps)}")
        print(f"     References: {'; '.join(ttp.references)}")
        print(f"     Notes: {'; '.join(ttp.notes)}")
        print(f"     TTP Chain: {'; '.join(ttp.ttp_chain)}")
        print("     Detection Rules:")
        for rule in ttp.detection_rules:
            print(f"       - Rule ID: {rule.rule_id}")
            print(f"         Creation Date: {rule.creation_date}")
            print(f"         Update Date: {rule.update_date}")
            print(f"         Description: {rule.description}")
            print(f"         Reference TTP: {rule.reference_ttp}")
            print(f"         Platforms: {'; '.join(rule.platforms)}")
            print(f"         Covered Techniques: {'; '.join(rule.coverage_techniques)}")
            print(f"         Sources: {'; '.join(rule.sources)}")
            print(f"         Language: {rule.language}")
            print(f"         Query: {rule.query}")
            print(f"         Notes: {'; '.join(rule.notes)}")
            print("         Validation:")
            if rule.validation:
                print(f"           - Status: {rule.validation.status}")
                print(f"             Update Date: {rule.validation.update_date}")
                print(f"             Dataset: {rule.validation.dataset}")
                print(f"             References: {'; '.join(rule.validation.references)}")
                print(f"             Notes: {'; '.join(rule.validation.notes)}")


def print_threat_text_area(threat: Threat, text_area: tk.Text, attck_src: str):
        """
        Imprime o objeto threat na text area.

        Args:
            threat (Threat): The Threat object to be printed.
            text_area (tk.Text): The text area where the threat data will be printed.
            attck_src (str): The source of the MITRE ATTACK data.
        """
        text_area.configure(state="normal")
        text_area.delete(1.0, tk.END)
        text_area.insert(tk.INSERT, f"Title: {threat.title}\n")
        text_area.insert(tk.INSERT, f"Threat ID: {threat.threat_id}\n")
        text_area.insert(tk.INSERT, f"Creation Date: {threat.creation_date}\n")
        text_area.insert(tk.INSERT, f"Update Date: {threat.update_date}\n")
        text_area.insert(tk.INSERT, f"Type: {threat.type}\n")
        text_area.insert(tk.INSERT, f"Domain: {threat.domain}\n")
        text_area.insert(tk.INSERT, f"Platforms: {'; '.join(threat.platforms)}\n")
        text_area.insert(tk.INSERT, f"Description: {threat.description}\n")
        text_area.insert(tk.INSERT, f"Related Threats: {'; '.join(threat.related_threats)}\n")
        text_area.insert(tk.INSERT, f"Notes: {'; '.join(threat.notes)}\n")
        text_area.insert(tk.INSERT, "References:\n")
        for ref in threat.references:
            text_area.insert(tk.INSERT, f"  - ID: {ref.ref_id}\n")
            text_area.insert(tk.INSERT, f"     Type: {ref.type}\n")
            text_area.insert(tk.INSERT, f"     Title: {ref.title}\n")
            text_area.insert(tk.INSERT, f"     Authors: {'; '.join(ref.authors)}\n")
            text_area.insert(tk.INSERT, f"     Date: {ref.date}\n")
            text_area.insert(tk.INSERT, f"     Link: {ref.link}\n")
            text_area.insert(tk.INSERT, f"     Notes: {'; '.join(ref.notes)}\n")
        text_area.insert(tk.INSERT, "TTPs:\n")
        for ttp in threat.ttps:
            text_area.insert(tk.INSERT, f"  - TTP ID: {ttp.ttp_id}\n")
            text_area.insert(tk.INSERT, f"     Tactic: {ttp.tactic} ({get_tactic_name(attck_src, ttp.tactic)})\n")
            text_area.insert(tk.INSERT, f"     Technique: {ttp.technique} ({get_technique_name(attck_src, ttp.technique)})\n")
            text_area.insert(tk.INSERT, f"     Procedure: {ttp.procedure}\n")
            #text_area.insert(tk.INSERT, f"     Secondary Techniques: {'; '.join(ttp.secondary_techniques)}\n")
            text_area.insert(tk.INSERT, f"     Secondary Techniques: {'; '.join([f"{secondary_technique} ({get_technique_name(attck_src, secondary_technique)})" for secondary_technique in ttp.secondary_techniques])}\n")
            text_area.insert(tk.INSERT, f"     Related TTPs: {'; '.join(ttp.related_ttps)}\n")
            text_area.insert(tk.INSERT, f"     References: {'; '.join(ttp.references)}\n")
            text_area.insert(tk.INSERT, f"     Notes: {'; '.join(ttp.notes)}\n")
            text_area.insert(tk.INSERT, f"     TTP Chain: {'; '.join(ttp.ttp_chain)}\n")
            text_area.insert(tk.INSERT, "     Detection Rules:\n")
            for rule in ttp.detection_rules:
                text_area.insert(tk.INSERT, f"       - Rule ID: {rule.rule_id}\n")
                text_area.insert(tk.INSERT, f"         Creation Date: {rule.creation_date}\n")
                text_area.insert(tk.INSERT, f"         Update Date: {rule.update_date}\n")
                text_area.insert(tk.INSERT, f"         Reference TTP: {rule.reference_ttp}\n")
                text_area.insert(tk.INSERT, f"         Description: {rule.description}\n")
                text_area.insert(tk.INSERT, f"         Platforms: {'; '.join(rule.platforms)}\n")
                #text_area.insert(tk.INSERT, f"         Covered Techniques: {'; '.join(rule.coverage_techniques)}\n")
                text_area.insert(tk.INSERT, f"         Covered Techniques: {'; '.join([f"{covered_technique} ({get_technique_name(attck_src, covered_technique)})" for covered_technique in rule.coverage_techniques])}\n")
                text_area.insert(tk.INSERT, f"         Sources: {'; '.join(rule.sources)}\n")
                text_area.insert(tk.INSERT, f"         Language: {rule.language}\n")
                text_area.insert(tk.INSERT, f"         Query: {rule.query}\n")
                text_area.insert(tk.INSERT, f"         Notes: {'; '.join(rule.notes)}\n")
                text_area.insert(tk.INSERT, "         Validation:\n")
                if rule.validation:
                    text_area.insert(tk.INSERT, f"           - Status: {rule.validation.status}\n")
                    text_area.insert(tk.INSERT, f"             Update Date: {rule.validation.update_date}\n")
                    text_area.insert(tk.INSERT, f"             Dataset: {rule.validation.dataset}\n")
                    text_area.insert(tk.INSERT, f"             References: {'; '.join(rule.validation.references)}\n")
                    text_area.insert(tk.INSERT, f"             Notes: {'; '.join(rule.validation.notes)}\n")
        text_area.configure(state="disabled")

def print_ttps_text_area(threat: Threat, text_area: tk.Text, attck_src: str):
        """
        Imprime as ttps do objeto threat na text area (sem as rules).

        Args:
            threat (Threat): The Threat object to be printed.
            text_area (tk.Text): The text area where the threat data will be printed.
            attck_src (str): The source of the MITRE ATTACK data.
        """
        text_area.configure(state="normal")
        text_area.delete(1.0, tk.END)
        for ttp in threat.ttps:
            text_area.insert(tk.INSERT, f"- TTP ID: {ttp.ttp_id}\n")
            text_area.insert(tk.INSERT, f"  Tactic: {ttp.tactic} ({get_tactic_name(attck_src, ttp.tactic)})\n")
            text_area.insert(tk.INSERT, f"  Technique: {ttp.technique} ({get_technique_name(attck_src, ttp.technique)})\n")
            text_area.insert(tk.INSERT, f"  Procedure: {ttp.procedure}\n")
            #text_area.insert(tk.INSERT, f"  Secondary Techniques: {'; '.join(ttp.secondary_techniques)}\n")
            text_area.insert(tk.INSERT, f"  Secondary Techniques: {'; '.join([f"{secondary_technique} ({get_technique_name(attck_src, secondary_technique)})" for secondary_technique in ttp.secondary_techniques])}\n")
            text_area.insert(tk.INSERT, f"  Related TTPs: {'; '.join(ttp.related_ttps)}\n")
            text_area.insert(tk.INSERT, f"  References: {'; '.join(ttp.references)}\n")
            text_area.insert(tk.INSERT, f"  Notes: {'; '.join(ttp.notes)}\n")
            text_area.insert(tk.INSERT, f"  TTP Chain: {'; '.join(ttp.ttp_chain)}\n")
            text_area.insert(tk.INSERT, f"  Detection Rules: {'; '.join([f"{rule.rule_id}" for rule in ttp.detection_rules])}\n")
        text_area.configure(state="disabled")

def print_rules_text_area(threat: Threat, text_area: tk.Text, attck_src: str):
        """
        Imprime as rules do objeto threat na text area.

        Args:
            threat (Threat): The Threat object to be printed.
            text_area (tk.Text): The text area where the threat data will be printed.
            attck_src (str): The source of the MITRE ATTACK data.
        """
        text_area.configure(state="normal")
        text_area.delete(1.0, tk.END)
        for ttp in threat.ttps:
            for rule in ttp.detection_rules:
                text_area.insert(tk.INSERT, f"- Rule ID: {rule.rule_id}\n")
                text_area.insert(tk.INSERT, f"  Creation Date: {rule.creation_date}\n")
                text_area.insert(tk.INSERT, f"  Update Date: {rule.update_date}\n")
                text_area.insert(tk.INSERT, f"  Reference TTP: {rule.reference_ttp}\n")
                text_area.insert(tk.INSERT, f"  Description: {rule.description}\n")
                text_area.insert(tk.INSERT, f"  Platforms: {'; '.join(rule.platforms)}\n")
                #text_area.insert(tk.INSERT, f"  Covered Techniques: {'; '.join(rule.coverage_techniques)}\n")
                text_area.insert(tk.INSERT, f"  Covered Techniques: {'; '.join([f"{covered_technique} ({get_technique_name(attck_src, covered_technique)})" for covered_technique in rule.coverage_techniques])}\n")
                text_area.insert(tk.INSERT, f"  Sources: {'; '.join(rule.sources)}\n")
                text_area.insert(tk.INSERT, f"  Language: {rule.language}\n")
                text_area.insert(tk.INSERT, f"  Query: {rule.query}\n")
                text_area.insert(tk.INSERT, f"  Notes: {'; '.join(rule.notes)}\n")
                text_area.insert(tk.INSERT, "  Validation:\n")
                if rule.validation:
                    text_area.insert(tk.INSERT, f"  - Status: {rule.validation.status}\n")
                    text_area.insert(tk.INSERT, f"    Update Date: {rule.validation.update_date}\n")
                    text_area.insert(tk.INSERT, f"    Dataset: {rule.validation.dataset}\n")
                    text_area.insert(tk.INSERT, f"    References: {'; '.join(rule.validation.references)}\n")
                    text_area.insert(tk.INSERT, f"    Notes: {'; '.join(rule.validation.notes)}\n")
        text_area.configure(state="disabled")

def print_selected_ref_listbox(ref_ids_listbox: tk.Listbox, threat: Threat, text_area: tk.Text):
    selection = ref_ids_listbox.curselection()
    if not selection:
        return
    selected_ref_id = ref_ids_listbox.get(selection)
    if not selected_ref_id:
        return
    selected_ref = next((ref for ref in threat.references if ref.ref_id == selected_ref_id), None)
    if selected_ref:
        text_area.configure(state="normal")
        text_area.delete("1.0", tk.END)
        text_area.tag_config('bold', font=('Arial', '10', 'bold'))
        text_area.insert(tk.INSERT, "ID: ", 'bold')
        text_area.insert(tk.END, f"{selected_ref.ref_id}\n")
        text_area.insert(tk.END, "Type: ", 'bold')
        text_area.insert(tk.END, f"{selected_ref.type}\n")
        text_area.insert(tk.END, "Title: ", 'bold')
        text_area.insert(tk.END, f"{selected_ref.title}\n")
        text_area.insert(tk.END, "Authors: ", 'bold')
        text_area.insert(tk.END, f"{'; '.join(selected_ref.authors)}\n")
        text_area.insert(tk.END, "Date: ", 'bold')
        text_area.insert(tk.END, f"{selected_ref.date}\n")
        text_area.insert(tk.END, "Link: ", 'bold')
        text_area.insert(tk.END, f"{selected_ref.link}\n")
        text_area.insert(tk.END, "Notes: ", 'bold')
        text_area.insert(tk.END, f"{'; '.join(selected_ref.notes)}\n")
        text_area.configure(state="disabled")
    else:
        print("Erro: selected_ref == None")
        text_area.configure(state="normal")
        text_area.delete("1.0", tk.END)
        text_area.configure(state="disabled")


def print_selected_ttp_listbox(ttp_ids_listbox: tk.Listbox, threat: Threat, text_area: tk.Text, attck_src: str):
    selection = ttp_ids_listbox.curselection()
    if not selection:
        return
    selected_new_ttp_id = ttp_ids_listbox.get(selection)
    if not selected_new_ttp_id:
        return
    selected_new_ttp = next((ttp for ttp in threat.ttps if ttp.ttp_id == selected_new_ttp_id), None)
    if selected_new_ttp:
        text_area.configure(state="normal")
        text_area.delete("1.0", tk.END)
        text_area.tag_config('bold', font=('Arial', '10', 'bold'))
        text_area.insert(tk.INSERT, "ID: ", 'bold')
        text_area.insert(tk.END, f"{selected_new_ttp.ttp_id}\n")
        text_area.insert(tk.END, "Tactic: ", 'bold')
        text_area.insert(tk.END, f"{selected_new_ttp.tactic} ({get_tactic_name(attck_src, selected_new_ttp.tactic)})\n")
        text_area.insert(tk.END, "Technique: ", 'bold')
        text_area.insert(tk.END, f"{selected_new_ttp.technique} ({get_technique_name(attck_src, selected_new_ttp.technique)})\n")
        text_area.insert(tk.END, "Procedure: ", 'bold')
        text_area.insert(tk.END, f"{selected_new_ttp.procedure}\n")
        text_area.insert(tk.END, "References: ", 'bold')
        text_area.insert(tk.END, f"{'; '.join(selected_new_ttp.references)}\n")
        text_area.insert(tk.END, "Secondary techniques:\n", 'bold')
        for secondary_technique in selected_new_ttp.secondary_techniques:
             text_area.insert(tk.INSERT, f"  - {secondary_technique} ({get_technique_name(attck_src, secondary_technique)})\n")
        text_area.insert(tk.END, "Related TTPs: ", 'bold')
        text_area.insert(tk.END, f"{'; '.join(selected_new_ttp.related_ttps)}\n")
        text_area.insert(tk.END, "TTP Chain: ", 'bold')
        text_area.insert(tk.END, f"{'; '.join(selected_new_ttp.ttp_chain)}\n")
        text_area.insert(tk.END, "Notes: ", 'bold')
        text_area.insert(tk.END, f"{'; '.join(selected_new_ttp.notes)}\n")
        text_area.configure(state="disabled")
    else:
        print("Erro: selected_ttp == None")
        text_area.configure(state="normal")
        text_area.delete("1.0", tk.END)
        text_area.configure(state="disabled")

#################################
# Funções de tradução
#################################

def get_locale() -> str:
    return _locale

def set_locale(locale: str) -> None:
    global _locale
    _locale = locale


def t(text: str) -> str:
    global _locale
    if _locale == "pt-BR":
        return text
    
    #Dicionario de tradução para inglês
    to_english = {
        #Menu
        "Arquivo" : "File",
        "Ferramentas" : "Tools",
        #Frames
        " ESTÁGIO 1 - Mapeamento Ameaça-TTP ": "STAGE 1 - Threat-TTP Mapping",
        " ESTÁGIO 2 - Mapeamento TTP-Dados ": "STAGE 2 - TTP-Data Mapping",
        " ESTÁGIO 3 - Validação ": "STAGE 3 - Validation",
        " ESTÁGIO 4 - Consolidação dos Resultados ": "STAGE 4 - Results Compilation",
        "Dados da Referência selecionada": "Selected Reference Data",
        "Dados da TTP selecionada": "Selected TTP Data",
        "Dados da Regra de Detecção selecionada": "Selected Detection Rule Data",
        #Labels
        "Geração do Runbook": "Runbook Generation",
        #Botões
        "<< Gerar": "<< Generate",
        "Inserir >>": "Insert >>",
        "Editar >>": "Edit >>",
        "Nova Referência": "New Reference",
        "Excluir Referência": "Delete Reference",
        "Nova TTP": "New TTP",
        "Excluir TTP": "Delete TTP",
        "Clonar TTP": "Clone TTP",
        "Nova Regra": "New Detection Rule",
        "Excluir Regra": "Delete Detection Rule",
        "Validar": "Validate",
        "Resetar": "Reset",
        "Gerar arquivo YAML": "Generate YAML File"
    }

    if _locale == "en-US":
        #print("Traduzindo " + text + " para " + to_english.get(text, text))
        return to_english.get(text, text)

    return text