import os

from lxml import etree


tag_dict = {}
    
    
def create_tag_dict(root):
    tag_dict['entry'] = r"{%s}entry" % root.nsmap[None]
    tag_dict['vuln:vulnerable-configuration'] = \
        r'{%s}vulnerable-configuration' % root.nsmap['vuln']
    tag_dict['vuln:summary'] = r'{%s}summary' % root.nsmap['vuln']
    tag_dict['cpe-lang:logical-test'] = r'{%s}logical-test' % root.nsmap['cpe-lang']
    tag_dict['vuln:vulnerable-software-list'] = \
        r'{%s}vulnerable-software-list' % root.nsmap['vuln']


def print_cve_entry(cve_id):
    year = int(cve_id.split("-")[1:2][0])
    if year < 2002:
        year = 2002

    file = open(os.path.join(os.environ['KAFTI_NVD_BASES_PATH'], 
                             "nvdcve-2.0-%s.xml" % year))
    root = etree.parse(file).getroot()
    
    create_tag_dict(root)
    
    for entry_tag in root.iter(tag_dict['entry']):
        if entry_tag.get("id") == cve_id:
            print etree.tostring(entry_tag, pretty_print=True)


if __name__ == "__main__":
    print_cve_entry("CVE-1999-1593")