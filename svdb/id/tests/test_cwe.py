import unittest

from svdb.id.cwe import CWEID


class CWETestCase(unittest.TestCase):
    
    def test_cwe_should_be_ok(self):
        cwe_str = "CWE-399"
        self.assertTrue(CWEID.correct_cwe_str(cwe_str))                

        cwe = CWEID(cwe_str)
        self.assertEqual(str(cwe), cwe_str)
        
    def test_cwe_lower_case_should_be_ok(self):
        cwe_str = "cwe-399"
        self.assertTrue(CWEID.correct_cwe_str(cwe_str))                

        cwe = CWEID(cwe_str)
        self.assertEqual(str(cwe), cwe_str)
        
    def test_cwe_should_be_bad_1(self):
        cwe_str = "CWE399"
        
        self.assertFalse(CWEID.correct_cwe_str(cwe_str))
        self.assertRaises(ValueError, CWEID, cwe_str)
        
    def test_cwe_should_be_bad_2(self):
        cwe_str = "CWE-AAA"
        
        self.assertFalse(CWEID.correct_cwe_str(cwe_str))
        self.assertRaises(ValueError, CWEID, cwe_str)
        
    def test_cwe_should_be_bad_3(self):
        cwe_str = "CWE-"
        
        self.assertFalse(CWEID.correct_cwe_str(cwe_str))
        self.assertRaises(ValueError, CWEID, cwe_str)
        
    def test_cwe_should_be_bad_4(self):
        cwe_str = "CWE-333A"
        
        self.assertFalse(CWEID.correct_cwe_str(cwe_str))
        self.assertRaises(ValueError, CWEID, cwe_str)
        
        
if __name__ == "__main__":
    unittest.main()