import unittest   # The test framework
import sys
sys.path.append('../../../../tools/pyelftool_parser/src')
import analyzer

class Test_TestFunctionSize(unittest.TestCase):
    def setUp(self):
        self.entry_function = "should_fail"
        self.path = "./ss.elf"
        self.stub_path = "../../../../../src/components/interface/init/kernel/stubs.S"
        self.driver = analyzer.driver(self.path, self.entry_function, self.stub_path)

    def teststacksize(self):
        self.driver.run()
        stack_size = self.driver.register.reg["max"]
        self.assertEqual(-8408, stack_size)
        result = self.driver.PowerOf2(abs(min(self.driver.parser.stacklist)))
        self.assertEqual(7, result)
        
if __name__ == '__main__':
    unittest.main()
    
    
