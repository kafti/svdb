import unittest

from svdb.id.cve import CVEID


class CVETestCase(unittest.TestCase):
    
    def test_cve_should_be_ok(self):
        cve_str = "CVE-2011-0346"
        
        self.assertTrue(CVEID.correct_cve_str(cve_str))                
        
        cve = CVEID(cve_str)
        
        self.assertEqual(cve.get_year(), 2011)
        self.assertEqual(cve.is_candidate(), False)
        self.assertEqual(str(cve), cve_str)
                
    def test_cve_equal_should_be_ok(self):
        cve_str = "CVE-2011-0346"
        cve = CVEID(cve_str)
        
        self.assertEqual(cve, CVEID(cve_str))
        self.assertNotEqual(cve, CVEID("CVE-2010-0346"))
        
    def test_cve_lower_case_should_be_ok(self):
        cve_str = "cve-2011-0346"
        
        self.assertTrue(CVEID.correct_cve_str(cve_str))                
        
        cve = CVEID(cve_str)
        
        self.assertEqual(cve.get_year(), 2011)
        self.assertEqual(cve.is_candidate(), False)
        self.assertEqual(str(cve), cve_str)
        
    def test_cve_should_be_bad_year(self):
        cve_str = "CVE-201-0346"
        
        self.assertFalse(CVEID.correct_cve_str(cve_str))
        self.assertRaises(ValueError, CVEID, cve_str)
        
    def test_cve_should_be_bad_name_1(self):
        cve_str = "CV-2011-0346"
        
        self.assertFalse(CVEID.correct_cve_str(cve_str))
        self.assertRaises(ValueError, CVEID, cve_str)
        
    def test_cve_should_be_bad_name_2(self):
        cve_str = "CVEE-2011-0346"
        
        self.assertFalse(CVEID.correct_cve_str(cve_str))
        self.assertRaises(ValueError, CVEID, cve_str)
        
    def test_cve_should_be_bad_number(self):
        cve_str = "CVE-20110346"
        
        self.assertFalse(CVEID.correct_cve_str(cve_str))
        self.assertRaises(ValueError, CVEID, cve_str)
        
        
    def test_can_should_be_ok(self):
        cve_str = "CAN-2011-0346"
        
        self.assertTrue(CVEID.correct_cve_str(cve_str))                
        
        cve = CVEID(cve_str)
        
        self.assertEqual(cve.get_year(), 2011)
        self.assertEqual(cve.is_candidate(), True)
        self.assertEqual(str(cve), cve_str)
        
    def test_can_lower_case_should_be_ok(self):
        cve_str = "can-2011-0346"
        
        self.assertTrue(CVEID.correct_cve_str(cve_str))                
        
        cve = CVEID(cve_str)
        
        self.assertEqual(cve.get_year(), 2011)
        self.assertEqual(cve.is_candidate(), True)
        self.assertEqual(str(cve), cve_str)
        
    def test_can_should_be_bad_year(self):
        cve_str = "CAN-201-0346"
        
        self.assertFalse(CVEID.correct_cve_str(cve_str))
        self.assertRaises(ValueError, CVEID, cve_str)
        
    def test_can_should_be_bad_name_1(self):
        cve_str = "CA-2011-0346"
        
        self.assertFalse(CVEID.correct_cve_str(cve_str))
        self.assertRaises(ValueError, CVEID, cve_str)
        
    def test_can_should_be_bad_name_2(self):
        cve_str = "CANN-2011-0346"
        
        self.assertFalse(CVEID.correct_cve_str(cve_str))
        self.assertRaises(ValueError, CVEID, cve_str)
        
    def test_can_should_be_bad_number(self):
        cve_str = "CAN-20110346"
        
        self.assertFalse(CVEID.correct_cve_str(cve_str))
        self.assertRaises(ValueError, CVEID, cve_str)


if __name__ == "__main__":
    unittest.main()