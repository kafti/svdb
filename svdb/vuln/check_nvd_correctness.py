#-------------------------------------------------------------------------------
# Copyright (c) 2011, Kafti team
# 
# Released under the MIT license. See the LICENSE file for details.
#-------------------------------------------------------------------------------

"""Script for checking correctness of NVD data"""

import logging
import time
from lxml import etree
import os


logger = logging.getLogger("servicesdb.vuln.test_nvd")
logger.setLevel(logging.INFO)


bad_cve_id_list = set()


tag_dict = {}


def is_or_elem(elem):
    return elem.tag == tag_dict['cpe-lang:logical-test'] and elem.get('operator') == 'OR'


def is_and_elem(elem):
    return elem.tag == tag_dict['cpe-lang:logical-test'] and elem.get('operator') == 'AND'


def print_dashes():
    logger.info("-" * 50)
    
    
def create_tag_dict(root):
    tag_dict['entry'] = "{%s}entry" % root.nsmap[None]
    tag_dict['vuln:vulnerable-configuration'] = '{%s}vulnerable-configuration' % root.nsmap['vuln']
    tag_dict['vuln:summary'] = '{%s}summary' % root.nsmap['vuln']
    tag_dict['cpe-lang:logical-test'] = '{%s}logical-test' % root.nsmap['cpe-lang']
    tag_dict['vuln:vulnerable-software-list'] = '{%s}vulnerable-software-list' % root.nsmap['vuln']
    tag_dict['vuln:cvss'] = '{%s}cvss' % root.nsmap['vuln']
    

def check_correctness(nvd_dir):

    begin_time_sec = time.time()

    logger.info("Begin testing nvd base")
    
    for file in os.listdir(nvd_dir):
        fullname = os.path.join(nvd_dir, file)
        if os.path.isfile(fullname) and file.startswith('nvd') and file.endswith('.xml'):
            logger.info(file)
            file = open(fullname)
            root = etree.parse(file).getroot()
            
            create_tag_dict(root)
            
            #print_dashes()
            #test_has_vulnerable_configuration_and_vulnerable_software_list(root)
            
            print_dashes()
            test_cvss(root)

            #probably not an error            
            #print_dashes()
            #test_multiple_vulnerable_configuration(root)
            
#            print_dashes()
#            test_has_logical_elem(root)
#            
#            print_dashes()
#            #not an error just interest
#            test_one_or_inside_and(root)
#            
            print_dashes()
            test_zero_or_inside_and(root)
            
            print_dashes()
            test_and_inside_or(root)
                
            print_dashes()
            test_or_inside_or(root)
            
            print_dashes()
            test_empty_or(root)
            
            print_dashes()
            test_empty_and(root)
            
#            print_dashes()
#            #not an error just interest
#            test_multiple_or_inside_and(root)
    
    
    print_dashes()
    logger.info("Testing done, takes %s sec" % (time.time() - begin_time_sec))
    

def test_cvss(root):
    counter = 0
    logger.info("Test if each entry element has cvss element")
    for entry in root.iter(tag_dict['entry']):
        cve_id = entry.get('id')
        
        if entry.find(tag_dict['vuln:cvss']) is None:
            #logger.info("cvss tag is absent for %s" % cve_id)
            bad_cve_id_list.add(cve_id)
            counter += 1
            
    logger.info("total errors find: %s" % counter)


def test_has_vulnerable_configuration_and_vulnerable_software_list(root):
    counter = 0
    logger.info("Test if each entry element has vulnerable_configuration element")
    for entry in root.iter(tag_dict['entry']):
        cve_id = entry.get('id')
        
        if entry.find(tag_dict['vuln:vulnerable-configuration']) is None:
            summary = entry.find(tag_dict['vuln:summary'])
            if not summary is None:
                if "** REJECT **" in summary.text:
                    continue
            bad_cve_id_list.add(cve_id)
            
            if entry.find(tag_dict['vuln:vulnerable-software-list']) is not None:
                pass
                #logger.info("vulnerable-software-list tag exist and vulnerable-configuration tag is absent in entry %s" % cve_id)
                #logger.info(etree.tostring(entry))
                #counter += 1
            else:
                pass
                #logger.info("vulnerable-configuration and vulnerable-software-list tag is absent in entry %s" % cve_id)
                #logger.info(etree.tostring(entry))
                #counter += 1
            
        elif entry.find(tag_dict['vuln:vulnerable-software-list']) is None:
            #logger.info("vulnerable-software-list tag is absent in entry %s" % cve_id)
            #logger.info(etree.tostring(entry))
            counter += 1
            
    logger.info("total errors find: %s" % counter)
        

def test_multiple_vulnerable_configuration(root):
    counter = 0
    logger.info("Test if each entry element has vulnerable_configuration element")
    for entry in root.iter(tag_dict['entry']):
        cve_id = entry.get('id')
        if len(entry.findall(tag_dict['vuln:vulnerable-configuration'])) > 1 :
            logger.info("multiple vulnerable-configuration tag for %s" % cve_id)
            #logger.info(etree.tostring(entry))
            bad_cve_id_list.add(cve_id)
            counter += 1
            
    logger.info("total errors find: %s" % counter)


def test_has_logical_elem(root):
    counter = 0
    logger.info("Test if each vulnerable-configuration element has logical element")
    for vuln_cfg in root.iter(tag_dict['vuln:vulnerable-configuration']):
        if vuln_cfg.find(tag_dict['cpe-lang:logical-test']) is None:
            cve_id = vuln_cfg.getParent().get('id')
            #logger.info("logical-test tag is absent in vulnerable-configuration for %s" % cve_id)
            #logger.info(etree.tostring(vuln_cfg))
            bad_cve_id_list.add(cve_id)
            counter += 1
            
    logger.info("total errors find: %s" % counter)
    
                
def test_one_or_inside_and(root):
    counter = 0
    logger.info("Test if one OR element could be found inside AND element")
    for vuln_cfg in root.iter(tag_dict['vuln:vulnerable-configuration']):
        cve_id = vuln_cfg.getparent().get('id')
        for lang in vuln_cfg:
            if is_and_elem(lang):
                if len(lang) == 1 and is_or_elem(lang[0]):
                    #logger.info("AND element has only one OR elements for %s" % cve_id)
                    #logger.info(etree.tostring(vuln_cfg))
                    bad_cve_id_list.add(cve_id)
                    counter += 1
            
    logger.info("total errors find: %s" % counter)


def test_zero_or_inside_and(root):
    counter = 0
    logger.info("Test if zero OR elements could be found inside AND elements")
    for vuln_cfg in root.iter(tag_dict['vuln:vulnerable-configuration']):
        cve_id = vuln_cfg.getparent().get('id')
        for lang in vuln_cfg:
            if is_and_elem(lang):
                has_or_elem = False
                for elem in lang:
                    if is_or_elem(elem):
                        has_or_elem = True
                        break
                if not has_or_elem:
                    #logger.info("AND element has no one OR elements for %s" % cve_id)
                    #logger.info(etree.tostring(vuln_cfg))
                    bad_cve_id_list.add(cve_id)
                    counter += 1
            
    logger.info("total errors find: %s" % counter)


def test_and_inside_or(root):
    counter = 0
    logger.info("Test if AND elements could be found inside OR elements")
    for vuln_cfg in root.iter(tag_dict['vuln:vulnerable-configuration']):
        cve_id = vuln_cfg.getparent().get('id')
        for lang in vuln_cfg.iter(tag_dict['cpe-lang:logical-test']):
            if is_or_elem(lang):
                found = False
                for elem in lang:
                    if is_and_elem(elem):
                        #logger.info(r"AND element found inside OR element for %s" % cve_id)
                        #logger.info(etree.tostring(vuln_cfg))
                        bad_cve_id_list.add(cve_id)
                        counter += 1
                        found = True
                        break
                if found == True:
                    break
            
    logger.info("total errors find: %s" % counter)
 
     
def test_or_inside_or(root):
    counter = 0
    logger.info("Test if OR elements could be found inside OR elements")
    for vuln_cfg in root.iter(tag_dict['vuln:vulnerable-configuration']):
        cve_id = vuln_cfg.getparent().get('id')
        for lang in vuln_cfg.iter(tag_dict['cpe-lang:logical-test']):
            if is_or_elem(lang):
                found = False
                for elem in lang:
                    if is_or_elem(elem):
                        #logger.info(r"OR element found inside OR element for %s" % cve_id)
                        #logger.info(etree.tostring(vuln_cfg))
                        bad_cve_id_list.add(cve_id)
                        counter += 1
                        found = True
                        break
                if found == True:
                    break
                    
    logger.info("total errors find: %s" % counter)


def test_empty_or(root):
    counter = 0
    logger.info("Test if empty OR element could be found (no one child element)")
    for vuln_cfg in root.iter(tag_dict['vuln:vulnerable-configuration']):
        cve_id = vuln_cfg.getparent().get('id')
        for lang in vuln_cfg.iter(tag_dict['cpe-lang:logical-test']):
            if is_or_elem(lang) and len(lang) == 0:
                #logger.info(r"Empty OR element found for %s" % cve_id)
                #logger.info(etree.tostring(vuln_cfg))
                bad_cve_id_list.add(cve_id)
                counter += 1
        
    logger.info("total errors find: %s" % counter)


def test_empty_and(root):
    counter = 0
    logger.info("Test if empty AND element could be found (no one child element)")
    for vuln_cfg in root.iter(tag_dict['vuln:vulnerable-configuration']):
        cve_id = vuln_cfg.getparent().get('id')
        for lang in vuln_cfg.iter(tag_dict['cpe-lang:logical-test']):
            if is_and_elem(lang) and len(lang) == 0:
                #logger.info(r"Empty AND element found for %s" % cve_id)
                #logger.info(etree.tostring(vuln_cfg))
                bad_cve_id_list.add(cve_id)
                counter += 1
        
    logger.info("total errors find: %s" % counter)


def test_multiple_or_inside_and(root):
    #not an error just interest
    logger.info("Test just print all entries which have more than two OR elements")
    for vuln_cfg in root.iter(tag_dict['vuln:vulnerable-configuration']):
        cve_id = vuln_cfg.getparent().get('id')
        for lang in vuln_cfg.iter(tag_dict['cpe-lang:logical-test']):
            if is_and_elem(lang):
                counter = 0
                for elem in lang:
                    if is_or_elem(elem):
                        counter += 1
                
                if counter > 2:
                    pass
                    #logger.info(cve_id)
                    #logger.info(etree.tostring(lang))


if __name__ == "__main__":
    logging.basicConfig(#filename='log.txt', filemode='w', 
                        format='%(asctime)s  %(levelname)-8s %(name)-25s %(message)s', 
                        datefmt='%H:%M')
    
    check_correctness(os.environ['KAFTI_NVD_BASES_PATH'])