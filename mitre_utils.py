# from stix2 import TAXIICollectionSource
#from taxii2client.v20 import Collection # only specify v20 if your installed version is >= 2.0.0
#from stix2 import FileSystemSource
from stix2 import MemoryStore
from stix2 import Filter, AttackPattern
#import pprint as pp

############## Source of ATT&CK Data ################

# def get_attck_source_from_server(collection_key: str = "enterprise_attack"):
#     collections = {
#         "enterprise_attack": "95ecc380-afe9-11e4-9b6c-751b66dd541e",
#         "mobile_attack": "2f669986-b40b-4423-b720-4396ca6a462b",
#         "ics_attack": "02c3ef24-9cd4-48f3-a99f-b74ce24f1d34"
#     }
#     collection = Collection(f"https://cti-taxii.mitre.org/stix/collections/{collections[collection_key]}/")
#     src = TAXIICollectionSource(collection)
#     return src

# def get_attck_source_from_local_filesystem(path: str = "./cti/enterprise-attack"):
#     #Tem que clonar o repositorio https://github.com/mitre/cti.git usano um cliente Git
#     src = FileSystemSource(path)
#     return src

def get_attck_source_from_local_json(path: str = "mitre/enterprise-attack.json"):
    #Baixar enterprise-attack.json de https://github.com/mitre/cti/tree/master/enterprise-attack
    #Baixar ics-attack.json de https://github.com/mitre/cti/tree/master/ics-attack
    #Baixar mobile-attack.json de https://github.com/mitre/cti/tree/master/mobile-attack
    src = MemoryStore()
    src.load_from_file(path)
    return src


############## General Functions ################

def remove_revoked_deprecated(stix_objects):
    """Remove any revoked or deprecated objects from queries made to the data source"""
    # Note we use .get() because the property may not be present in the JSON data. The default is False
    # if the property is not set.
    return list(
        filter(
            lambda x: x.get("x_mitre_deprecated", False) is False and x.get("revoked", False) is False,
            stix_objects
        )
    )

def remove_revoked(stix_objects):
    """Remove any revoked or deprecated objects from queries made to the data source"""
    if not stix_objects:
        return stix_objects
    # Note we use .get() because the property may not be present in the JSON data. The default is False
    # if the property is not set.
    return list(
        filter(
            lambda x: x.get("revoked", False) is False,
            stix_objects
        )
    )

def remove_deprecated(stix_objects):
    """Remove any deprecated objects from queries made to the data source"""
    if not stix_objects:
        return stix_objects
    # Note we use .get() because the property may not be present in the JSON data. The default is False
    # if the property is not set.
    return list(
        filter(
            lambda x: x.get("x_mitre_deprecated", False) is False,
            stix_objects
        )
    )

############## get-Object Functions ################

def get_object_by_technique_id(src, technique_id, except_revoked: bool = True, except_deprecated: bool = True) -> AttackPattern:
    # Documentação da classe AttackPattern em https://stix2.readthedocs.io/en/latest/api/stix2.v21.html
    try:
        stix_obj_list = src.query([
            Filter("external_references.external_id", "=", technique_id), 
            Filter("type", "=", "attack-pattern")
        ])
    except Exception as e:
        print(f"Erro ao consultar o src: {e}")
        return None
    if except_revoked:
        stix_obj_list = remove_revoked(stix_obj_list)
    if except_deprecated:
        stix_obj_list = remove_deprecated(stix_obj_list)
    if not stix_obj_list:
        return None
    return stix_obj_list[0]
    

def get_object_by_tactic_id(src, tactic_id, except_revoked: bool = True, except_deprecated: bool = True)  -> dict:
    try:
        stix_obj_list = src.query([
            Filter("external_references.external_id", "=", tactic_id),
            Filter("type", "=", "x-mitre-tactic")
        ])
    except Exception as e:
        print(f"Erro ao consultar o src: {e}")
        return None
    if not stix_obj_list:
        return None
    if except_revoked:
        stix_obj_list = remove_revoked(stix_obj_list)
    if except_deprecated:
        stix_obj_list = remove_deprecated(stix_obj_list)
    if not stix_obj_list:
        return None
    return stix_obj_list[0]



############## speccific Functions ################

def get_technique_name(src, technique_id, except_revoked = False, except_deprecated = False):
    stix_obj = get_object_by_technique_id(src, technique_id, except_revoked, except_deprecated)
    if not stix_obj:
        return None
    #Se é subtecnica pega o nome da tecnica pai e concatena com o nome da subtecnica
    if stix_obj.x_mitre_is_subtechnique:
        subtech_name = stix_obj.name
        tech_id = technique_id.split(".")[0]
        stix_obj_tech = get_object_by_technique_id(src, tech_id)
        if stix_obj:
            name = stix_obj_tech.name + ": " + subtech_name
    else:
        #Se é técnica retorna o nome
        name = stix_obj.name
    #Se o objeto foi revogado, concatena com (revoked)
    if not except_revoked and stix_obj.get("revoked", False):
        name = name + " (revoked)"
    #Se o objeto foi deprecated, concatena com (deprecated)
    if not except_deprecated and stix_obj.get("x_mitre_deprecated", False):
        name = name + " (deprecated)"
    return name

def get_tactic_name(src, tactic_id, except_revoked = False, except_deprecated = False):
    stix_obj = get_object_by_tactic_id(src, tactic_id)
    if not stix_obj:
        return None
    name = stix_obj['name']
    #Se o objeto foi revogado, concatena com (revoked)
    if not except_revoked and stix_obj.get("revoked", False):
        name = name + " (revoked)"
    #Se o objeto foi deprecated, concatena com (deprecated)
    if not except_deprecated and stix_obj.get("x_mitre_deprecated", False):
        name = name + " (deprecated)"
    return name

############## TESTE ################

#attck_src = get_attck_source_from_server()
#attck_src = get_attck_source_from_local_json()


#pp.pprint(get_object_by_tactic_id(attck_src, "TA0004"))
#print(get_tactic_name(attck_src, "TA0004"))

#pp.pprint(get_object_by_technique_id(attck_src, "T1065"))
#print(get_technique_name(attck_src, "T1134.001"))




