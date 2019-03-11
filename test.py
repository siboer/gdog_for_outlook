import unittest
import siboer
import glob
import os
import sys

class Test_Siboer(unittest.TestCase):
				
				def setUp(self):
						self.sibo = siboer.Siboer()
				def tearDown(self):
						test_directory = os.path.dirname(os.path.realpath(__file__))
						for pyc in glob.glob('%s/*.pyc' % test_directory) :
									sys.stdout.write("removing '{}'\n".format(pyc))
									os.remove(pyc)
					
				def test_checkclients(self):
						self.assertIn('e929f47f5c4347cf7027e8ffb6e546136f099ce51e1130a32a556de93fd94956',self.sibo.checkclients())

						

if __name__ == '__main__':
			unittest.main()