import sys
from pathlib import Path
import pewee.imports


if hasattr(sys, 'getwindowsversion'):
	win_ver = sys.getwindowsversion()
else:
	import collections
	getwindowsversion = collections.namedtuple('getwindowsversion', ('major', 'minor', 'build', 'service_pack_major'))
	win_ver = getwindowsversion(major=10, minor=0, build=10586, service_pack_major=0)


def test_filter():
	assert pewee.imports.should_filter('kernel32.dll', win_ver)
	assert not pewee.imports.should_filter('archive.dll', win_ver)


def test_search_dll():
	assert Path(__file__).parent / 'fixtures' / 'archive.dll' == pewee.imports.search_dll(Path(__file__).parent / 'fixtures' / 'archi.cp38-win_amd64-afd0fc2d962751c372762df64bd05eb08185b744.pyd', 'archive.dll', win_ver, safe_dll_search_mode=True)
	assert not pewee.imports.search_dll(Path(__file__).parent / 'fixtures' / 'archi.cp38-win_amd64-afd0fc2d962751c372762df64bd05eb08185b744.pyd', 'python38.dll', win_ver, safe_dll_search_mode=True)
