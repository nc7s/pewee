'''Module to determine which DLLs are to be packed in, and where to put them.

There are three categories we needn't pack:

1. Known DLLs, which Windows always load from its own cache;
2. API Sets, which are another indirection of Known DLLs (for now), and there's no reason to pack them;
3. PythonXY.dll, because it is needed to run Python, and it should exist before installing a wheel.

To reduce workload, Windows versions below Windows 7 (NT 6.1) are not supported.
Microsoft themselves ended support for them, after all.

After filtering out those, find the correct DLLs loaded by native extensions,
following the search order described at https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order.
Only follow the default (standard) Desktop Application search order is followed for now,
ignoring Windows Store apps, DLL redirections, and manifests.
'''


import re
import os
import sys
from pathlib import Path


class UnsupportedWindowsVersion(Exception): pass


PYTHON_DLL_RE = re.compile('^python\d{2}\.dll', re.IGNORECASE)
ENVIRONMENT_PATHS = os.getenv('PATH').split(os.pathsep)
# Known DLLs list courtesy of https://windowssucks.wordpress.com/knowndlls/. Thanks!
# After reading https://lucasg.github.io/2017/06/07/listing-known-dlls/, I decided to use a simple list,
# rather than going through the Windows APIs.
KNOWN_DLLS_COMMON = frozenset({'setupapi.dll', 'normaliz.dll', 'ole32.dll', 'comdlg32.dll', 'kernel32.dll', 'shell32.dll', 'crypt32.dll', 'msvcrt.dll', 'sechost.dll', 'nsi.dll', 'cfgmgr32.dll', 'shlwapi.dll', 'msctf.dll', 'ntdll.dll', 'user32.dll', 'wintrust.dll', 'oleaut32.dll', 'ws2_32.dll', 'psapi.dll', 'gdi32.dll', 'comctl32.dll', 'difxapi.dll', 'advapi32.dll', 'clbcatq.dll', 'rpcrt4.dll', 'msasn1.dll', 'wldap32.dll', 'imagehlp.dll', 'kernelbase.dll', 'imm32.dll'})
KNOWN_DLLS_COMMON_WIN10 = frozenset({'windows.storage.dll', 'shcore.dll', 'combase.dll', 'gdiplus.dll', 'powrprof.dll', 'profapi.dll', 'coml2.dll', 'kernel.appcore.dll'})
KNOWN_DLLS_WIN7 = frozenset({'wininet.dll', 'iertutil.dll', 'lpk.dll', 'urlmon.dll', 'usp10.dll', 'devobj.dll'})
KNOWN_DLLS_WIN8 = frozenset({'wininet.dll', 'iertutil.dll', 'combase.dll', 'lpk.dll', 'userenv.dll', 'gdiplus.dll', 'urlmon.dll', 'devobj.dll', 'profapi.dll'})
KNOWN_DLLS_WIN8_1 = frozenset({'shcore.dll', 'gdiplus.dll', 'combase.dll'})
KNOWN_DLLS_WIN10_10586 = frozenset({'bcryptprimitives.dll', 'netapi32.dll', 'firewallapi.dll'})


if sys.platform.startswith('win32'):
	import ctypes
	_BUF_SIZE = 256
	buf = ctypes.create_unicode_buffer(_BUF_SIZE)
	ctypes.cdll.kernel32.GetSystemDirectoryW(ctypes.byref(buf), _BUF_SIZE)
	SYSTEM_DIRECTORY = Path(buf.value)
	ctypes.cdll.kernel32.GetWindowsDirectoryW(ctypes.byref(buf), _BUF_SIZE)
	WINDOWS_DIRECTORY = Path(buf.value)


def _make_known_dlls_list(win_ver):
	'''Generate a set containing names of Known DLLs in given version of Windows.

	:param win_ver: The named tuple returned by `sys.getwindowsversion()`.
	:returns: A tuple of Known DLLs.
	'''
	if win_ver.major == 10:
		known_dlls = KNOWN_DLLS_COMMON.union(KNOWN_DLLS_COMMON_WIN10)
		if win_ver.build >= 10586:
			known_dlls = known_dlls.union(KNOWN_DLLS_WIN10_10586)
	elif win_ver.major == 6:
		if win_ver.minor == 1: # Windows 7
			known_dlls = KNOWN_DLLS_COMMON.union(KNOWN_DLLS_WIN7)
		elif win_ver.minor == 2: # Windows 8
			known_dlls = KNOWN_DLLS_COMMON.union(KNOWN_DLLS_WIN8)
		elif win_ver.minor == 3: # Windows 8.1
			known_dlls = KNOWN_DLLS_COMMON.union(KNOWN_DLLS_WIN8_1)
		elif win_ver.minor == 0: # Vista
			raise UnsupportedWindowsVersion(win_ver)
	else: # NT5 and below
		raise UnsupportedWindowsVersion(win_ver)
	return known_dlls


def should_filter(imported, win_ver=None):
	if not win_ver:
		win_ver = sys.getwindowsversion()
	known_dlls = _make_known_dlls_list(win_ver)
	
	if imported in known_dlls:
		return True
	elif imported.startswith('api-ms-win'): # API Sets
		return True
	elif PYTHON_DLL_RE.match(imported):
		return True
	return False


def is_safe_dll_search_mode_enabled(win_ver):
	'''Query the Windows registry to determine if SafeDllSearchMode is enabled. Windows only.

	:param win_ver: The named tuple returned by `sys.getwindowsversion()`.
	:returns: A bool, True if SafeDllSearchMode is enabled.
	'''
	import winreg
	reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Control\Session Manager')
	try:
		return winreg.QueryValueEx(reg_key, 'SafeDllSearchMode')[0] == 1
	except: # No value present, use default value
		# Enabled by default starting in Windows XP SP2
		return win_ver.major >= 6 or (win_ver.major == 5 and win_ver.service_pack_major >= 2)


def _search_directory(directory, name_lower):
	for item in Path(directory).iterdir():
		if item.name.lower() == name_lower:
			return item.absolute()


def _search_system_directories(name_lower):
	'''Search through system directory then Windows directory. Windows only.'''
	# Although listed, we don't actually have a canonical way to get the 16-bit system directory.
	return _search_directory(SYSTEM_DIRECTORY) or _search_directory(WINDOWS_DIRECTORY)


def _search_PATH(name_lower):
	result = None
	for path in os.getenv('PATH').split(os.pathsep):
		result = _search_directory(path, name_lower)
		if result:
			return result


def search_dll(importer_path, name, win_ver=None, working_directory=None, safe_dll_search_mode=None):
	'''Search the DLL that's actually imported by importer, i.e. the importing `.pyd` or DLL.
	
	Depending on whether SafeDllSearchMode is enabled, there are two search orders:

	* SafeDllSearchMode is ENABLED
	 1. The directory from which the application is loaded, e.g. where the importer is located;
	 2. The system directory, e.g. C:\Windows\System32;
	 3. The 16-bit system directory (not actually, but it's listed);
	 4. The Windows directory, e.g. C:\Windows;
	 5. The current directory;
	 6. The directories listed in the PATH environment variable.
	* SafeDllSearchMode is DISABLED
	 1. The directory from which the application is loaded, e.g. where the importer is located;
	 2. The current directory;
	 3. The system directory, e.g. C:\Windows\System32;
	 4. The 16-bit system directory (not actually, but it's listed);
	 5. The Windows directory, e.g. C:\Windows;
	 6. The directories listed in the PATH environment variable.

	:param importer_path: Path of the importer.
	:param name: Name of the DLL to search for.
	:param working_directory: Defaults to `os.getcwd()`, but can be specified if that's the case.
	:param safe_dll_search_mode: Specify whether SafeDllSearchMode is enabled, or leave as None to query the registry.
	:returns: A `pathlib.Path` holding the path if found, otherwise `None`.
	'''
	if not win_ver:
		win_ver = os.getwindowsversion()
	if safe_dll_search_mode is None:
		safe_dll_search_mode = is_safe_dll_search_mode_enabled(win_ver)
	name_lower = name.lower()
	current_directory = Path(working_directory or os.getcwd())
	
	path = _search_directory(Path(importer_path).parent, name_lower)
	if not path:
		if sys.platform.startswith('win32'):
			if safe_dll_search_mode:
				path = _search_system_directories(name_lower) or _search_directory(current_directory, name_lower)
			else:
				path = _search_directory(current_directory, name_lower) or _search_system_directories(name_lower)
		# Not on a Windows, no "system" directories to search for.
		else:
			path = _search_directory(current_directory, name_lower)
	if not path:
		_search_PATH(name_lower)
	return path
