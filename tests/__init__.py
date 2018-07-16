import sys
import os

__appname = 'letmein'
__path_to_app = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), __appname))
sys.path.insert(0, __path_to_app)
