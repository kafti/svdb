#-------------------------------------------------------------------------------
# Copyright (c) 2011, Kafti team
# 
# Released under the MIT license. See the LICENSE file for details.
#-------------------------------------------------------------------------------

"""Staff for working with CVE Identifiers. See http://cve.mitre.org."""

import re


class CVEID(object):
    """
    CVEID class.
    CVE Identifiers (also called "CVE names," "CVE numbers," "CVE-IDs," and "CVEs") 
    are unique, common identifiers for publicly known information security vulnerabilities.
    See http://cve.mitre.org.
    """
    
    @classmethod
    def correct_cve_str(cls, cve_str):
        return re.match(r'^CVE-[\d]{4}-[\d]+|CAN-[\d]{4}-[\d]+$', cve_str, re.I)
            
    def __init__(self, cve_str):
        if not CVEID.correct_cve_str(cve_str):
            raise ValueError
        self._cve_str = cve_str
    
    def __str__(self):
        return self._cve_str
    
    def __eq__(self, other):
        if not isinstance(other, CVEID):
            raise ValueError
        return self._cve_str.upper() == other._cve_str.upper()

    def get_year(self):
        """
        @return: value of the cve year.
        Mast be integer value
        """
        res = re.search('[\d]{4}', self._cve_str)
        return int(res.group(0))
    
    def is_candidate(self):
        """
        @return: True if cve id has candidate status. False otherwise.
        """
        return self._cve_str.startswith('CAN') or self._cve_str.startswith('can')