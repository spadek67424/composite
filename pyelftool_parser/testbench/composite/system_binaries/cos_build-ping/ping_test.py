import unittest   # The test framework
import sys
sys.path.append('/home/minghwu/work/composite/pyelftool_parser/src')
from analyzer import testdriver

class Test_TestFunctionSize(unittest.TestCase):
    def setUp(self):
        testdriver()
    def test(self):
        ## test printf_core
        ## self.assertEqual(self.stacklist[18], -496)
        self.assertEqual(0, -1)
        
if __name__ == '__main__':
    unittest.main()
    
    
