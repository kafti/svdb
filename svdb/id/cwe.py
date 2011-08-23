#-------------------------------------------------------------------------------
# Copyright (c) 2011, Kafti team
# 
# Released under the MIT license. See the LICENSE file for details.
#-------------------------------------------------------------------------------

"""Staff for working with CWE Identifiers. See http://cwe.mitre.org/"""

import re


class CWEID(object):
    """
    CWEID class.
    CWE list's element identifier.
    The Common Weakness Enumeration (CWE) is a list of software weaknesses.
    See http://cwe.mitre.org.
    """
    
    @classmethod
    def correct_cwe_str(cls, cwe_str):
        return re.match(r'^CWE-[\d]+$', cwe_str, re.I)
            
    def __init__(self, cwe_str):
        if not CWEID.correct_cwe_str(cwe_str):
            raise ValueError
        self._cwe_str = cwe_str
    
    def __str__(self):
        return self._cwe_str
    
    def __eq__(self, other):
        if not isinstance(other, CWEID):
            raise ValueError
        return self._cwe_str.upper() == other._cwe_str.upper()