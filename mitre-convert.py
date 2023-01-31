
import json
import sys
import re
import os


def load_data():
    '''
    Attempt to open latest instance of MITRE ATT&CK
    '''
    mitre = 'enterprise-attack.json'
    data = None
    try:
        with open(mitre, 'r') as f:
            data = json.load(f)
        return data
    except FileNotFoundError:
        sys.exit(-1)


def dump_object(obj : dict, path : str, id : str, verbose=False):
    '''
    Take a MITRE ATT&CK object, and use json.dumps to dump the obj to the correct path
    under enterprise/<path>/<id>.json
    '''
    #if not os.path.exists(os.path.join(os.getcwd(), path)):
    #    os.system('mkdir {}'.format(os.path.join(os.getcwd(), 'enterprise', path)))
    with open(os.path.join(os.getcwd(), 'enterprise/{}/{}.json'.format(path, id)), 'w') as f:
        if verbose:
            print('Writing: {}'.format(f.name))
        f.write(json.dumps(obj, indent=3))


def scan_for_ttps(mitre : dict):
    '''
    Iterate over objects in nested dictionary, scan for tactics, techniques, groups and software

    Methodology:
        * Iterate over external references to get an idea of which code is associated to the object
            * G[0-9]*  - Group
            * TA[0-9]* - Tactic
            * T[0-9]*  - Technique
            * S[0-9]*  - Software
    '''
    # MITRE ATT&CK Field Names
    EXT_REF      = 'external_references'
    EXT_ID       = 'external_id'
    TYPE         = 'type'
    ATK_PTRN     = 'attack-pattern'
    TACTIC       = 'x-mitre-tactic'
    SOFTWARE     = ['tool', 'malware']
    INTR_SET     = 'intrusion-set'
    DATA_COMP    = 'x-mitre-data-component'
    NAME         = 'name'
    RELATIONSHIP = 'relationship' 
    ID           = 'id'
    DATA_SRC     = 'x-mitre-data-source'
    CAMPAIGN     = 'campaign'


    # Decrease verbosity of printing
    passed_tech     = False
    passed_tactic   = False
    passed_group    = False
    passed_software = False
    passed_dc       = False
    passed_rel      = False
    passed_data_src = False
    passed_campaign = False

    # Dictionary to hold mapping of technique code to uuid str
    tcode_2_uuid = {}
    
    for object in mitre['objects']:
        # Not all objects have ext ref, so skip those
        dumped_obj = False
        if EXT_REF in object.keys():
            for ref in object[EXT_REF]:
                # Not all references have external_ids
                if EXT_ID in ref.keys() and TYPE in object.keys():
                    if re.match('T[0-9][0-9]*', ref[EXT_ID]) and object[TYPE] == ATK_PTRN:
                        if not passed_tech:
                            print("Technique: {}".format(ref[EXT_ID]))
                        dump_object(object, 'technique', ref[EXT_ID])
                        if ref[EXT_ID] not in tcode_2_uuid.keys():
                            tcode_2_uuid[ref[EXT_ID]] = object[ID] # Add in mapping for tcode to uuid

                        dumped_obj = True
                        passed_tech = True
                    
                    elif re.match('TA[0-9][0-9][0-9][0-9]', ref[EXT_ID]) and object[TYPE] == TACTIC:
                        if not passed_tactic:
                            print("Tactic: {}".format(ref[EXT_ID]))
                        dump_object(object, 'tactics', ref[EXT_ID])
                        dumped_obj = True
                        passed_tactic = True
                    
                    elif re.match('S[0-9][0-9][0-9][0-9]', ref[EXT_ID]) and object[TYPE] in SOFTWARE:
                        if not passed_software:
                            print("Software: {}".format(ref[EXT_ID]))
                        dump_object(object, 'software', ref[EXT_ID])
                        dumped_obj = True
                        passed_software = True
                    
                    elif re.match('G[0-9][0-9][0-9][0-9]', ref[EXT_ID]) and object[TYPE] == INTR_SET:
                        if not passed_group:
                            print("Group: {}".format(ref[EXT_ID]))
                            print("APT: {}".format(object[NAME]))
                        dump_object(object, 'groups', ref[EXT_ID])
                        dump_object(object, 'intrusion-set', object[NAME])
                        dumped_obj = True
                        passed_group = True

                    elif re.match('DS[0-9][0-9][0-9][0-9]', ref[EXT_ID]) and object[TYPE] == DATA_SRC:
                        if not passed_data_src:
                            print("Datasource: {}".format(ref[EXT_ID]))
                        dump_object(object, 'datasource', ref[EXT_ID])
                        dumped_obj = True
                        passed_data_src = True

                    elif re.match('C[0-9][0-9][0-9][0-9]', ref[EXT_ID]) and object[TYPE] == CAMPAIGN:
                        if not passed_campaign:
                            print("Campaign: {}".format(ref[EXT_ID]))
                             
                        dump_object(object, 'campaign', ref[EXT_ID])
                        dumped_obj = True
                        passed_campaign = True
            
        if TYPE in object.keys() and not dumped_obj:
            if object[TYPE] == DATA_COMP:
                dc_name = object[NAME].replace(" ", "_")
                if not passed_dc:
                    print('Data-Component: {}'.format(dc_name))
                dump_object(object, 'data-component', dc_name)
                passed_dc = True

            elif object[TYPE] == RELATIONSHIP:
                if not passed_rel:
                    print('Relationship: {}'.format(object[ID]))
                dump_object(object, 'relationships', object[ID])
                passed_rel = True

            elif object[TYPE] == INTR_SET:
                if not passed_apt:
                    print('APT: {}'.format(object[NAME]))
                dump_object(object, 'intrusion-set', object[NAME])
                passed_apt = True

    with open('mappings-tech2uuid.json', 'w') as f:
        f.write(json.dumps(tcode_2_uuid, indent=3))


if __name__ == '__main__':
    mitre = load_data()
    scan_for_ttps(mitre)