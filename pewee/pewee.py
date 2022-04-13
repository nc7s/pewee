import pefile
from pathlib import Path
from tempfile import TemporaryDirectory
from shutil import copy
from subprocess import run
from .imports import search_dll, should_include, WIN_VER, SYSTEM_DIRECTORY, WINDOWS_DIRECTORY


def find_imports(files, work_dir=None, win_ver=WIN_VER):
	if isinstance(files, (str, Path)):
		files = [files]

	names = set()
	paths = set()
	stack = files[:]

	while stack:
		current = stack.pop()
		pe = pefile.PE(current)

		# No imports at all
		if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
			continue

		for imp in pe.DIRECTORY_ENTRY_IMPORT:
			name = imp.dll.decode()
			name_lower = name.lower()
			if name_lower in names or not should_include(name_lower, win_ver):
				continue
			names.add(name_lower)
			path = search_dll(name, work_dir)
			if path:

				# Check if it's in a system directory and made by Microsoft,
				# which means it's likely some sort of system DLL.
				if WIN_VER:
					if path.is_relative_to(SYSTEM_DIRECTORY) or path.is_relative_to(WINDOWS_DIRECTORY):
						pe = pefile.PE(path)
						try:
							if pe.FileInfo[0][0].StringTable[0].entries[b'CompanyName'] == b'Microsoft Corporation':
								# With the exception of VC redistributables
								if not path.name.lower().startswith('vcruntime') and not path.name.lower().startswith('msvc'):
									continue
						except:
							pass
				paths.add(path)
				stack.append(path)
	return paths


def patch_wheel(wheel_path, work_dir=None, dest_dir=None, echo=False):
	'''Patch the wheel. If `dest_dir` is omitted, override the original wheel.'''
	if dest_dir is None:
		dest_dir = Path(wheel_path).parent
	
	with TemporaryDirectory() as temp_dir:
		run(('wheel', 'unpack', wheel_path, '-d', temp_dir), check=True)

		pack_dir = Path(temp_dir).iterdir().send(None)

		importer_map = {}
		for file in Path(pack_dir).iterdir():
			if file.suffix == '.pyd':
				if file.parent not in importer_map:
					importer_map[file.parent] = []
				importer_map[file.parent].append(file)

		import_map = {}
		for dir, importers in importer_map.items():
			if dir not in import_map:
				import_map[dir] = set()
			import_map[dir].update(find_imports(importers, work_dir))

		for dir, imports in import_map.items():
			for imp in imports:
				if echo:
					print(f'copying {imp} to {dir / imp.name}')
				copy(imp, dir / imp.name)

		run(('wheel', 'pack', pack_dir, '-d', dest_dir))
