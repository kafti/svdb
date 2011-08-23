import datetime
import logging
import os
import time

from lxml import etree

import check_nvd_correctness
import svdb.vuln.vulnerability as vuln
from svdb.id.cve import CVEID
from svdb.id.cpe import CPEID
from svdb.id.cwe import CWEID
from svdb.id.cvss import *


logger = logging.getLogger("svdb.vuln.test_nvd")
logger.setLevel(logging.INFO)


tag_dict = {}


def is_or_elem(elem):
    return elem.tag == tag_dict['cpe-lang:logical-test'] and elem.get('operator') == 'OR'


def is_and_elem(elem):
    return elem.tag == tag_dict['cpe-lang:logical-test'] and elem.get('operator') == 'AND'


def is_fact_ref(elem):
    return elem.tag == tag_dict['cpe-lang:fact-ref']
    

def create_tag_dict(root):
    
    tag_dict['entry'] = "{%s}entry" % root.nsmap[None]
    
    tag_dict['vuln:vulnerable-configuration'] = '{%s}vulnerable-configuration' % root.nsmap['vuln']
    tag_dict['vuln:vulnerable-software-list'] = '{%s}vulnerable-software-list' % root.nsmap['vuln']
    tag_dict['vuln:cve-id'] = '{%s}cve-id' % root.nsmap['vuln']
    tag_dict['vuln:published-datetime'] = '{%s}published-datetime' % root.nsmap['vuln']
    tag_dict['vuln:last-modified-datetime'] = '{%s}last-modified-datetime' % root.nsmap['vuln']
    tag_dict['vuln:cvss'] = '{%s}cvss' % root.nsmap['vuln']
    tag_dict['vuln:cwe'] = '{%s}cwe' % root.nsmap['vuln']
    tag_dict['vuln:references'] = '{%s}references' % root.nsmap['vuln']
    tag_dict['vuln:summary'] = '{%s}summary' % root.nsmap['vuln']
    
    tag_dict['cpe-lang:logical-test'] = '{%s}logical-test' % root.nsmap['cpe-lang']
    tag_dict['cpe-lang:fact-ref'] = '{%s}fact-ref' % root.nsmap['cpe-lang']
    
    tag_dict['cvss:base_metrics'] = '{%s}base_metrics' % root.nsmap['cvss']
    tag_dict['cvss:score'] = '{%s}score' % root.nsmap['cvss']
    tag_dict['cvss:access-vector'] = '{%s}access-vector' % root.nsmap['cvss']
    tag_dict['cvss:access-complexity'] = '{%s}access-complexity' % root.nsmap['cvss']
    tag_dict['cvss:authentication'] = '{%s}authentication' % root.nsmap['cvss']
    tag_dict['cvss:confidentiality-impact'] = '{%s}confidentiality-impact' % root.nsmap['cvss']
    tag_dict['cvss:integrity-impact'] = '{%s}integrity-impact' % root.nsmap['cvss']
    tag_dict['cvss:availability-impact'] = '{%s}availability-impact' % root.nsmap['cvss']
    tag_dict['cvss:source'] = '{%s}source' % root.nsmap['cvss']
    tag_dict['cvss:generated-on-datetime'] = '{%s}generated-on-datetime' % root.nsmap['cvss']


def parseEntry(entry):
    
    vulnObject = vuln.Vulnerability()
    
    cve_id = entry.get('id')
    vulnObject.cve = CVEID(cve_id)
        
    for elem in entry:
        if elem.tag == tag_dict['vuln:vulnerable-configuration']:
            vulnObject.condition.conidtion_variants.append(parseVulnConfig(elem))
        elif elem.tag == tag_dict['vuln:vulnerable-software-list']:
            vulnObject.products = parseVulnSoftwareList(elem)
        elif elem.tag == tag_dict['vuln:cve-id']:
            pass
        elif elem.tag == tag_dict['vuln:published-datetime']:
            vulnObject.published_datetime = parsePublishedDateTime(elem)
        elif elem.tag == tag_dict['vuln:last-modified-datetime']:
            vulnObject.last_modified_datetime = parseLastModifDateTime(elem)
        elif elem.tag == tag_dict['vuln:cvss']:
            vulnObject.cvss_base_metrics = parseCVSS(elem)
        elif elem.tag == tag_dict['vuln:cwe']:
            vulnObject.cwe = CWEID(elem.get('id'))
        elif elem.tag == tag_dict['vuln:references']:
            vulnObject.references.append(parseVulnerabilityReference(elem))
        elif elem.tag == tag_dict['vuln:summary']:
            vulnObject.summary = elem.text
        
        #parse first 'cpe-lang:logical-test' (should be OR)
        if entry.find(tag_dict['vuln:vulnerable-software-list']) is None:
            vuln_conf_elem = entry.find(tag_dict['vuln:vulnerable-configuration'])
            vulnObject.products = parseVulnConfigSoftwareList(vuln_conf_elem)
    
    
    if vulnObject.cve is None or \
    vulnObject.products is None or \
    len(vulnObject.products) == 0 or \
    len(vulnObject.condition.conidtion_variants) == 0 or \
    vulnObject.cvss_base_metrics is None:
        return None
                 
    return vulnObject


def parseVulnConfig(elem):
    
    conditionGroup = vuln.VulnConditionGroup()
    
    for elem_le in elem:
        #IS OR
        if is_or_elem(elem_le):
            choice = vuln.VulnConditionChoice()
            choice.negate = (elem_le.get('negate') == 'true')
            #FACT REF
            choice.choice_list = [CPEID(elem_fe.get('name')) 
                                       for elem_fe in elem_le 
                                       if is_fact_ref(elem_fe)]
            
            conditionGroup.group_choice_list.append(choice)
                
        #IS AND        
        elif is_and_elem(elem_le):
            #IS OR
            for elem_or in elem_le:
                #FACT REF
                choice = vuln.VulnConditionChoice()
                choice.choice_list = [CPEID(elem_fe.get('name')) 
                                       for elem_fe in elem_or 
                                       if is_fact_ref(elem_fe)]
                
                conditionGroup.group_choice_list.append(choice)
                
    return conditionGroup


def parseVulnSoftwareList(elem):
    return [CPEID(cpe_elem.text) for cpe_elem in elem]


def parseVulnConfigSoftwareList(elem):
    if elem is not None:
        log_entr_elem = elem[0]
        if log_entr_elem is not None:
            if len(log_entr_elem) > 0:
                if not is_fact_ref(log_entr_elem[0]):
                    log_entr_elem = log_entr_elem[0]
            return [CPEID(cpe_elem.get('name')) for cpe_elem in log_entr_elem]
    return None


def _parseISO8601Time(str):
    #TODO: make time parsing better
    return datetime.datetime(*time.strptime(str[0:-11], "%Y-%m-%dT%H:%M:%S")[:6])


def parsePublishedDateTime(elem):
    return _parseISO8601Time(elem.text)


def parseLastModifDateTime(elem):
    return _parseISO8601Time(elem.text)


def parseCVSS(elem):
    bm = CVSSBaseMetrics()
    
    for cvss_elem in elem:
        if cvss_elem.tag == tag_dict['cvss:base_metrics']:
            for bm_elem in cvss_elem:        
                if bm_elem.tag == tag_dict['cvss:score']:
                    bm.score = float(bm_elem.text)
                elif bm_elem.tag == tag_dict['cvss:access-vector']:
                    bm.access_vector = ACCESS_VECTOR_VALUES.from_string(bm_elem.text)
                elif bm_elem.tag == tag_dict['cvss:access-complexity']:
                    bm.access_complexity = ACCESS_COMPLEXITY_VALUES.from_string(bm_elem.text)
                elif bm_elem.tag == tag_dict['cvss:authentication']:
                    bm.authentication = AUTHENTICATION_VALUES.from_string(bm_elem.text)
                elif bm_elem.tag == tag_dict['cvss:confidentiality-impact']:
                    bm.confidentiality_impact = IMPACT_VALUES.from_string(bm_elem.text)
                elif bm_elem.tag == tag_dict['cvss:integrity-impact']:
                    bm.integrity_impact = IMPACT_VALUES.from_string(bm_elem.text)
                elif bm_elem.tag == tag_dict['cvss:availability-impact']:
                    bm.availability_impact = IMPACT_VALUES.from_string(bm_elem.text)
                elif bm_elem.tag == tag_dict['cvss:source']:
                    pass
                elif bm_elem.tag == tag_dict['cvss:generated-on-datetime']:
                    #bm.generated_datetime = _parseISO8601Time(bm_elem.text)
                    pass
        
    return bm
     

def parseVulnerabilityReference(elem):
    ref = vuln.VulnerabilityReference()
    return ref


def parse_nvd_file(fullname, bad_cve_id_list = None):
    
    if os.path.isfile(fullname) and fullname.endswith('.xml'):
        logger.info(fullname)
        file = open(fullname)
        root = etree.parse(file).getroot()
        
        create_tag_dict(root)
        
        for entry in root.iter(tag_dict['entry']):
            if bad_cve_id_list != None:
                if entry.get('id') in bad_cve_id_list:
                    continue
            
            vulnObject = parseEntry(entry)
            
            yield vulnObject
            
            
if __name__ == "__main__":
    logging.basicConfig(#filename='log.txt', filemode='w', 
                        format='%(asctime)s  %(levelname)-8s %(name)-25s %(message)s', 
                        datefmt='%H:%M')
    
    check_nvd_correctness.check_correctness(os.environ['KAFTI_NVD_BASES_PATH'])
    
    
    logger.info("Begin parsing nvd base")
    
    begin_time_sec = time.time()

    good_nvd_entries_counter = 0
    bad_nvd_entries_counter = 0

    nvd_dir = os.environ['KAFTI_NVD_BASES_PATH']
    for file in os.listdir(nvd_dir):
        if file.startswith('nvd'):
            fullname = os.path.join(nvd_dir, file)
            for vulnObject in parse_nvd_file(fullname, check_nvd_correctness.bad_cve_id_list):
                if vulnObject is None:
                    bad_nvd_entries_counter += 1
                else:
                    good_nvd_entries_counter += 1
    

    logger.info("Parsing done, takes %s sec" % (time.time() - begin_time_sec))
    logger.info("Bad nvd entries count = %s" % bad_nvd_entries_counter)
    logger.info("Good nvd entries count = %s" % good_nvd_entries_counter)
            
