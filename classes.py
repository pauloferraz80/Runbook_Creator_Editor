from typing import List

class Reference:
    def __init__(self, 
                 ref_id: str = '', 
                 type: str = '', 
                 title: str = '',
                 authors: List[str] = [], 
                 date: str = '', 
                 link: str = '',
                 notes: List[str] = []):
        self.ref_id = ref_id
        self.type = type
        self.title = title
        self.authors = authors
        self.date = date
        self.link = link
        self.notes = notes

class Validation:
    def __init__(self, status: str = '', #unchecked, failed, validated, outdated
                 update_date: str = '',
                 dataset: str = '',
                 references: List[str] = [],
                 notes: List[str] = []):
        self.status = status
        self.update_date = update_date
        self.dataset = dataset
        self.references = references
        self.notes = notes

class DetectionRule:
    def __init__(self,
                rule_id: str = '',
                creation_date: str = '',
                update_date: str = '',
                description: str = '',
                platforms: List[str] = [],
                sources: List[str] = [],
                language: str = '',
                query: str = '',
                notes: List[str] = [],
                reference_ttp: str = '',
                coverage_techniques: List[str] = [],
                validation: 'Validation' = None):
        self.rule_id = rule_id
        self.creation_date = creation_date
        self.update_date = update_date
        self.description = description
        self.platforms = platforms
        self.sources = sources
        self.language = language
        self.query = query
        self.notes = notes
        self.reference_ttp = reference_ttp
        self.coverage_techniques = coverage_techniques
        self.validation = validation

class TTP:
    def __init__(self,
                ttp_id:str = '',
                tactic:str = '',
                technique:str = '',
                procedure: str = '',
                ttp_chain: List[str]  = [],
                notes: List[str] = [],
                references: List[str] = [],
                secondary_techniques: List[str] = [],
                related_ttps: List[str] = [],
                detection_rules: List['DetectionRule'] = []):
        self.ttp_id = ttp_id
        self.tactic = tactic
        self.technique = technique
        self.procedure = procedure
        self.ttp_chain = ttp_chain
        self.notes = notes
        self.references = references
        self.secondary_techniques = secondary_techniques
        self.related_ttps = related_ttps
        self.detection_rules = detection_rules

class Threat:
    def __init__(self,
                 title: str = '',
                 threat_id: str = '',
                 creation_date: str = '',
                 update_date: str = '',
                 type: str = '',
                 domain: str = '',
                 platforms: List[str] = [],
                 description: str = '',
                 references: List[Reference] = [],
                 ttps: List[TTP] = [],
                 related_threats: List[str] = [],
                 notes: List[str] = []):
        self.title = title
        self.threat_id = threat_id
        self.creation_date = creation_date
        self.update_date = update_date
        self.type = type
        self.domain = domain
        self.platforms = platforms
        self.description = description
        self.references = references
        self.ttps = ttps
        self.related_threats = related_threats
        self.notes = notes

