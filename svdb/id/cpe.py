#-------------------------------------------------------------------------------
# Copyright (c) 2011, Kafti team
# 
# Released under the MIT license. See the LICENSE file for details.
#-------------------------------------------------------------------------------

"""Staff for working with CPE identifiers. See http://cpe.mitre.org."""

import re

class CPEID(object):
    """
    CPE identifier (name) class.
    CPE is a structured naming scheme for information technology systems, platforms, and packages.
    See http://cpe.mitre.org.
    """
    
    pattern = r'^cpe:/(?P<part>[hoa]):(?P<vendor>[^:]+):(?P<product>[^:]+):?(?P<version>[^:]*):?(?P<update>[^:]*):?(?P<edition>[^:]*):?(?P<language>[^:]*)$'
    
    @classmethod
    def correct_cpe_str(cls, cpe_str):
        return re.match(cls.pattern, cpe_str, re.I)
        
    def __init__(self, cpe_str='', part='', vendor='', 
                 product='', version='', update='', edition='', language = ''):
        """
        @param cpe_str: string with full cpe identifier.
            If this parameter is set other parameters will be ignored.
        @param part: string with type of service the particular platform part.
            Correct values:
            'h' - hardware part
            'o' - operation system part
            'a' - application part
        @param vendor: string with the supplier or vendor of the platform part.
        @param product: string with the product name of the platform part.
        @param version: string with the product name of the platform part.
        @param update: string with the version of the platform part.
        @param edition: string with the update or service pack information.
        """
        
        if not isinstance(cpe_str, (str, unicode)):
            raise TypeError("parameter 'cpe_str' must be a string")
        
        if cpe_str != '':
            if not CPEID.correct_cpe_str(cpe_str):
                raise ValueError("parameter 'cpe_str' contains wrong data")
            self._cpe_str = cpe_str
            #other parameters will be ignored if parameter cpe_str is set
            return
        
   
        #if parameter cpe_str is not set
        
        if not isinstance(part, (str, unicode)):
            raise TypeError("parameter 'part' must be a string")
        elif part == '':
            raise ValueError("parameter 'part' contains wrong data")
        
        if not isinstance(vendor, (str, unicode)):
            raise TypeError("parameter 'vendor' must be a string")
        elif vendor == '':
            raise ValueError("parameter 'vendor' contains wrong data")
        
        if not isinstance(product, (str, unicode)):
            raise TypeError("parameter 'product' must be a string")
        elif product == '':
            raise ValueError("parameter 'product' contains wrong data")
            
        self._cpe_str = 'cpe:/%s:%s:%s' % (part, vendor, product)
        
        if version != '':
            self._cpe_str += ':%s' % version
            
        if update != '':
            if version == '':
                self._cpe_str += ':'
            self._cpe_str += ':%s' % update
            
        if edition != '':
            if version == '':
                self._cpe_str += ':'
            if update == '':
                self._cpe_str += ':'
            self._cpe_str += ':%s' % edition

        if language != '':
            if edition == '':
                self._cpe_str += ':'
            if version == '':
                self._cpe_str += ':'
            if update == '':
                self._cpe_str += ':'
            self._cpe_str += ':%s' % language
        
    def __str__(self):
        return self._cpe_str
    
    def __eq__(self, other):
        if not isinstance(other, CPEID):
            raise ValueError
        return self._cpe_str.upper() == other._cpe_str.upper()
    
    def get_base_cpeid(self):
        """
        @return: CPEID object with base cpe info: part, vendor, product.
        """
        return CPEID('cpe:/%s:%s:%s' % (self.get_part_info(), 
                                  self.get_vendor_info(), self.get_product_info()))
        
    def _get_param(self, param_name):
        res = re.search(self.pattern, self._cpe_str, re.I)
        if res is None:
            return ''
        return res.group(param_name)
    
    def get_part_info(self):
        """
        @return: string with type of service the particular platform part.
        Correct values:
            'h' - hardware part
            'o' - operation system part
            'a' - application part
        """
        return self._get_param('part')
        
    def get_vendor_info(self):
        """
        @return: string with the supplier or vendor of the platform part.
        """
        return self._get_param('vendor')
        
    def get_product_info(self):
        """
        @return: string with the product name of the platform part.
        """
        return self._get_param('product')      
        
    def get_version_info(self):
        """
        @return: string with the version of the platform part.
        """
        return self._get_param('version')      
        
    def get_update_info(self):
        """
        @return: string with the update or service pack information.
        """
        return self._get_param('update')   
    
    def get_edition_info(self):
        """
        @return: string with the edition of the platform part.
        """
        return self._get_param('edition')        
        
    def get_language_info(self):
        """
        @return: string with the language associated with the specific platform.
        
        This component should be represented by a valid language tag as defined by IETF 
        RFC 4646 entitled Tags for Identifying Languages.
        """
        return self._get_param('language')

    def generalize(self, cpe):
        """
        @param cpe: CPEID object.
        @return: True if self object cpe generalize param cpe otherwise False.
        """
        if not isinstance(cpe, CPEID):
            return False
        return cpe._cpe_str.upper().startswith(self._cpe_str.upper()) and \
            len(self._cpe_str) < len(cpe._cpe_str)
