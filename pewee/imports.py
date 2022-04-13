'''Determine which DLLs are to be packed in.

There are three categories that needn't be packed:

1. Known DLLs, which Windows always load from its own cache;
2. API Sets, which are an indirection of Known DLLs (for now), so there's no reason to pack them;
3. PythonXY.dll, because it is needed to run Python, and it should exist before installing a wheel.

To simplify workload, Windows versions below (not including) Windows 7 (NT 6.1) are not supported.
Microsoft themselves ended support for them, after all.

After filtering out those, find the correct DLLs loaded by native extensions,
following the search order described at https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order.
Only the default (standard) Desktop Application search order is followed for now,
ignoring Windows Store (UWP) Apps, DLL redirections, `LOAD_LIBRARY_PATH`, and manifests.

Since native extensions are only built, not run,
the loading directory and working directory can be safely considered the same.
'''


import re
import os
import sys
from pathlib import Path


class UnsupportedWindowsVersion(Exception): pass


# Ignored: PythonXY.dll
IGNORE_DLL_RE = re.compile(r'^(python\d{2,3})\.dll$', re.IGNORECASE)
# Known DLLs list courtesy of https://windowssucks.wordpress.com/knowndlls/. Thanks!
# After reading https://lucasg.github.io/2017/06/07/listing-known-dlls/,
# I decided to use a simple list, rather than going through the Windows APIs.
KNOWN_DLLS_COMMON = frozenset({'setupapi.dll', 'normaliz.dll', 'ole32.dll', 'comdlg32.dll', 'kernel32.dll', 'shell32.dll', 'crypt32.dll', 'msvcrt.dll', 'sechost.dll', 'nsi.dll', 'cfgmgr32.dll', 'shlwapi.dll', 'msctf.dll', 'ntdll.dll', 'user32.dll', 'wintrust.dll', 'oleaut32.dll', 'ws2_32.dll', 'psapi.dll', 'gdi32.dll', 'comctl32.dll', 'difxapi.dll', 'advapi32.dll', 'clbcatq.dll', 'rpcrt4.dll', 'msasn1.dll', 'wldap32.dll', 'imagehlp.dll', 'kernelbase.dll', 'imm32.dll'})
KNOWN_DLLS_COMMON_WIN10 = frozenset({'windows.storage.dll', 'shcore.dll', 'combase.dll', 'gdiplus.dll', 'powrprof.dll', 'profapi.dll', 'coml2.dll', 'kernel.appcore.dll'})
KNOWN_DLLS_WIN7 = frozenset({'wininet.dll', 'iertutil.dll', 'lpk.dll', 'urlmon.dll', 'usp10.dll', 'devobj.dll'})
KNOWN_DLLS_WIN8 = frozenset({'wininet.dll', 'iertutil.dll', 'combase.dll', 'lpk.dll', 'userenv.dll', 'gdiplus.dll', 'urlmon.dll', 'devobj.dll', 'profapi.dll'})
KNOWN_DLLS_WIN8_1 = frozenset({'shcore.dll', 'gdiplus.dll', 'combase.dll'})
KNOWN_DLLS_WIN10_10586 = frozenset({'bcryptprimitives.dll', 'netapi32.dll', 'firewallapi.dll'})
KNOWN_DLLS_WIN10_1803 = frozenset({'fltlib.dll', 'gdi32full.dll', 'msvcp_win.dll', 'ucrtbase.dll', 'wow64.dll', 'wow64cpu.dll', 'wow64win.dll', 'wowarmhw.dll'})
KNOWN_DLLS_WIN10_1803_REMOVED = frozenset({'netapi32.dll'})


WIN_VER = None
SYSTEM_DIRECTORY = None
WINDOWS_DIRECTORY = None
if sys.platform.startswith('win32'):
	import ctypes
	_BUF_SIZE = 256
	buf = ctypes.create_unicode_buffer(_BUF_SIZE)
	ctypes.cdll.kernel32.GetSystemDirectoryW(ctypes.byref(buf), _BUF_SIZE)
	SYSTEM_DIRECTORY = Path(buf.value)
	ctypes.cdll.kernel32.GetWindowsDirectoryW(ctypes.byref(buf), _BUF_SIZE)
	WINDOWS_DIRECTORY = Path(buf.value)
	WIN_VER = sys.getwindowsversion()


def _make_known_dlls_list(win_ver=WIN_VER):
	'''Generate a frozenset containing names of Known DLLs in given version of Windows.

	:param win_ver: The named tuple `sys.getwindowsversion()` returns. It's called if omitted.
	:returns: A tuple of Known DLLs.
	'''
	if win_ver.major == 10:
		known_dlls = KNOWN_DLLS_COMMON.union(KNOWN_DLLS_COMMON_WIN10)
		if win_ver.build >= 10586:
			known_dlls = known_dlls.union(KNOWN_DLLS_WIN10_10586)
		if win_ver.build >= 17134: # 1803 has the build number 17134
			known_dlls = known_dlls.union(KNOWN_DLLS_WIN10_1803).difference(KNOWN_DLLS_WIN10_1803_REMOVED)
	elif win_ver.major == 6:
		if win_ver.minor == 1: # Windows 7
			known_dlls = KNOWN_DLLS_COMMON.union(KNOWN_DLLS_WIN7)
		elif win_ver.minor == 2: # Windows 8
			known_dlls = KNOWN_DLLS_COMMON.union(KNOWN_DLLS_WIN8)
		elif win_ver.minor == 3: # Windows 8.1
			known_dlls = KNOWN_DLLS_COMMON.union(KNOWN_DLLS_WIN8_1)
		elif win_ver.minor == 0: # Vista
			raise UnsupportedWindowsVersion(win_ver)
	else: # NT 5 and below
		raise UnsupportedWindowsVersion(win_ver)
	return known_dlls


def should_include(name, win_ver=WIN_VER):
	'''Determine if a given DLL name should be included.

	:param win_ver: The named tuple `sys.getwindowsversion()` returns. It's queried if omitted.
	'''
	known_dlls = _make_known_dlls_list(win_ver)
	
	if name in known_dlls:
		return False
	elif name.startswith('api-ms-win'): # API Sets
		return False
	elif IGNORE_DLL_RE.match(name):
		return False
	return True


def is_safe_dll_search_mode_enabled(win_ver=WIN_VER):
	'''Determine if SafeDllSearchMode is enabled.

	Tries to query the Windows registry; if value is absent or current platform is not Windows,
	return default value on `win_ver` version (enabled since Windows XP SP2).

	:param win_ver: The named tuple `sys.getwindowsversion()` returns. It's queried if omitted.
	:returns: bool, True if SafeDllSearchMode is enabled.
	'''
	try:
		import winreg
		with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Control\Session Manager') as reg_key:
			return winreg.QueryValueEx(reg_key, 'SafeDllSearchMode')[0] == 1
	except: # Value absent or not on Windows, use default value
		return win_ver.major >= 6 #or (win_ver.major == 5 and win_ver.service_pack_major >= 2)


def _search_directory(directory, name_lower):
	dir = Path(directory)
	if not dir.is_dir():
		return
	for item in dir.iterdir():
		if item.name.lower() == name_lower:
			return item.absolute()


def _search_system_directories(name_lower):
	# Although listed, we don't actually have a canonical way to get the 16-bit system directory.
	return _search_directory(SYSTEM_DIRECTORY, name_lower) or _search_directory(WINDOWS_DIRECTORY, name_lower)


def _search_PATH(name_lower):
	result = None
	for path in os.getenv('PATH', '').split(os.pathsep):
		result = _search_directory(path, name_lower)
		if result:
			return result


def search_dll(name, work_dir=None):
	'''Search the DLL that's actually imported.
	
	For the search order used, see module docstring.

	:param name: Name of the DLL to search for. Remember to include `.dll`.
	:param work_dir: This should be where the native extension is built. Defaults to `os.getcwd()`.
	:returns: A `pathlib.Path` holding the path if found, otherwise `None`.
	'''
	name_lower = name.lower()
	work_dir = Path(work_dir or os.getcwd())
	print('search_dll', name, work_dir)
	
	path = _search_directory(work_dir, name_lower)

	if not path:
		if sys.platform.startswith('win32'):
				path = _search_system_directories(name_lower)
		# Otherwise not on a Windows, no "system" directories to search for.

	if not path:
		_search_PATH(name_lower)

	return path
