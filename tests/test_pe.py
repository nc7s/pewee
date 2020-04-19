from pathlib import Path
import pewee


pe = None


def test_pe_load_and_parse_coff():
	global pe
	pe = pewee.PE(Path(__file__).parent / 'fixtures' / 'archi.cp38-win_amd64-afd0fc2d962751c372762df64bd05eb08185b744.pyd')


def test_read_imported_dlls():
	global pe
	assert set(e.name.lower() for e in pe.data_tables[1].entries) == {'archive.dll', 'python38.dll', 'kernel32.dll', 'vcruntime140.dll', 'api-ms-win-crt-runtime-l1-1-0.dll'}
