import os
import subprocess
from hatchling.builders.hooks.plugin.interface import BuildHookInterface

class MakeHook(BuildHookInterface):
    def initialize(self, version, build_data):
        # Define the tar
        # get output directory
        build_dir = os.path.join(self.root, 'libwg')

        # Run the Makefile
        subprocess.run(['make'], cwd=build_dir, check=True)
