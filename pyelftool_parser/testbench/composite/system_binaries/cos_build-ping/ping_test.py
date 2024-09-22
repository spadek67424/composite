import unittest   # The test framework
import sys
sys.path.append('/home/minghwu/work/composite/pyelftool_parser/src')
import analyzer

class Test_TestFunctionSize(unittest.TestCase):
    def setUp(self):
        basic_block_flag = 0
        entry_function = "__cosrt_upcall_entry"
        path = "./tests.unit_pingpong.global.ping"
        stub_path = "../../../../../src/components/interface/" + "pong" + "/stubs/stubs.S"
        self.driver = analyzer.driver(path, entry_function, stub_path, basic_block_flag)
        self.driver.run()
    def test(self):
        
        result = self.driver.PowerOf2(abs(min(self.driver.parser.stacklist)))
        assert(12, result)
        
if __name__ == '__main__':
    unittest.main()
    
    
