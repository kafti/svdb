import unittest

from svdb.id.cpe import CPEID


class CPETestCase(unittest.TestCase):
    
    def test_cve_should_be_ok(self):
        cpe_str = "CPE:/a:microsoft:ie:8.0.7600.16385"
        
        self.assertTrue(CPEID.correct_cpe_str(cpe_str))                
        
        cpe = CPEID(cpe_str)
        
        self.assertEqual(cpe.get_part_info(), 'a')
        self.assertEqual(cpe.get_vendor_info(), 'microsoft')
        self.assertEqual(cpe.get_product_info(), 'ie')
        self.assertEqual(cpe.get_version_info(), '8.0.7600.16385')
        self.assertEqual(cpe.get_edition_info(), '')
        self.assertEqual(cpe.get_language_info(), '')
        self.assertEqual(str(cpe), cpe_str)
        
    def test_cve_should_be_equal(self):
        cpe_str = "CPE:/a:microsoft:ie:8.0.7600.16385"
        cpe = CPEID(cpe_str)
        
        self.assertEqual(cpe, CPEID(cpe_str))
        
    def test_cve_should_not_be_equal(self):
        cpe_str = "CPE:/a:microsoft:ie:8.0.7600.16385"
        cpe = CPEID(cpe_str)
        
        self.assertNotEqual(cpe, CPEID("CPE:/a:microsoft:ie:9.0.7600.16385"))
        
    def test_base_cpeid_should_be_equal(self):
        cpe_str = "CPE:/a:microsoft:ie:8.0.7600.16385"
        cpe = CPEID(cpe_str)
        
        self.assertEqual(cpe.get_base_cpeid(), CPEID("cpe:/a:microsoft:ie"))
        
    def test_base_cpeid_should_not_be_equal(self):
        cpe_str = "CPE:/a:microsoft:ie:8.0.7600.16385"
        cpe = CPEID(cpe_str)
        
        self.assertNotEqual(cpe.get_base_cpeid(), CPEID("CPE:/a:microsoft:word"))
        
    def test_cve_generalize_should_be_ok(self):
        self.assertTrue(CPEID("CPE:/a:microsoft:ie").
                        generalize(CPEID("CPE:/a:microsoft:ie:8.0.7600.16385")))
        self.assertTrue(CPEID("CPE:/a:microsoft:ie").
                        generalize(CPEID("cpe:/a:microsoft:ie:9.0.7600.16385")))
        
    def test_cve_creation_additional_params_should_be_ok(self):
        #if cve_stris present all other parameters will be ignores
        cpe_str = "CPE:/a:microsoft:ie:8.0.7600.16385"
        cpe = CPEID(cpe_str, part='h', vendor='qqq', 
                 product='qqq', version='qqq', update='qqq', 
                 edition='qqq', language = 'qqq')
        
        self.assertEqual(cpe.get_part_info(), 'a')
        self.assertEqual(cpe.get_vendor_info(), 'microsoft')
        self.assertEqual(cpe.get_product_info(), 'ie')
        self.assertEqual(cpe.get_version_info(), '8.0.7600.16385')
        self.assertEqual(cpe.get_edition_info(), '')
        self.assertEqual(cpe.get_language_info(), '')
        self.assertEqual(str(cpe), cpe_str)
        
    def test_cve_creation_only_additional_params_should_be_ok(self):
        #if cve_stris is not present all other parameters will not be ignores
        
        cpe = CPEID(part='a', vendor='microsoft', 
                 product='ie', version='8.0.7600.16385', update='1', 
                 edition='2', language = 'en')
        
        self.assertEqual(cpe.get_part_info(), 'a')
        self.assertEqual(cpe.get_vendor_info(), 'microsoft')
        self.assertEqual(cpe.get_product_info(), 'ie')
        self.assertEqual(cpe.get_version_info(), '8.0.7600.16385')
        self.assertEqual(cpe.get_update_info(), '1')
        self.assertEqual(cpe.get_edition_info(), '2')
        self.assertEqual(cpe.get_language_info(), 'en')
        self.assertEqual(str(cpe).upper(), 
                         "CPE:/a:microsoft:ie:8.0.7600.16385:1:2:en".upper())
        
    def test_cve_creation_should_not_be_ok_1(self):
        cpe_str = "CE:/a:microsoft:ie:8.0.7600.16385"
        self.assertFalse(CPEID.correct_cpe_str(cpe_str))   
        self.assertRaises(ValueError, CPEID, cpe_str)
    
    def test_cve_creation_should_not_be_ok_2(self):
        cpe_str = "CPE:/x:microsoft:ie:8.0.7600.16385"
        self.assertFalse(CPEID.correct_cpe_str(cpe_str))   
        self.assertRaises(ValueError, CPEID, cpe_str)
        
    def test_cve_creation_should_not_be_ok_3(self):
        cpe_str = "CPE:/a:microsoft"
        self.assertFalse(CPEID.correct_cpe_str(cpe_str))   
        self.assertRaises(ValueError, CPEID, cpe_str)
        
        
if __name__ == "__main__":
    unittest.main()