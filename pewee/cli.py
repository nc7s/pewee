import os
import click
from pathlib import Path
from click import echo
from .pewee import patch_wheel


@click.group()
def cli():
	pass


@cli.command(help='Patch specified wheel.')
@click.option('-w', '--work-dir', help='working directory, current directory if omitted')
@click.option('-d', '--dest-dir', help='destination directory, current directory if omitted')
@click.argument('wheel')
def patch(wheel, work_dir, dest_dir):
	if work_dir is None:
		work_dir = os.getcwd()
	if dest_dir is None:
		dest_dir = os.getcwd()
	echo(f'Patching {Path(wheel).absolute()}')
	echo(f'Working directory {work_dir}')
	try:
		patch_wheel(wheel, work_dir, dest_dir)
	except:
		exit(1)

