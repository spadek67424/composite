import unittest   # The test framework
import sys
sys.path.append('/home/minghwu/work/composite/pyelftool_parser/src')
import analyzer

class Test_TestFunctionSize(unittest.TestCase):
    def setUp(self):
        self.entry_function = "__cosrt_upcall_entry"
        self.path = "./capmgr.simple.global.capmgr"
        self.stub_path = "../../../../../src/components/interface/" + "capmgr" + "/stubs/stubs.S"
        
    def setupmode(self, basic_block_flag):
        self.driver = analyzer.driver(self.path, self.entry_function, self.stub_path, basic_block_flag)
        
    def teststacksize(self):
        self.setupmode(0)
        self.driver.run()
        result = self.driver.PowerOf2(abs(min(self.driver.parser.stacklist)))
        self.assertEqual(14, result)
    def testbasicblock(self):
        self.setupmode(1)
        self.driver.run()
        result = self.driver.PowerOf2(abs(min(self.driver.parser.stacklist)))
        self.assertEqual(13, result)
if __name__ == '__main__':
    unittest.main()
    
    
