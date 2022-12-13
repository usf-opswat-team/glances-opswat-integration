#!/bin/bash
mkdir -p ./backup/glances/outputs
mkdir -p ./backup/glances/plugins
cp ../glances/glances/processes.py ./backup/glances/processes.py
cp ../glances/glances/outputs/glances_curses.py ./backup/glances/outputs/glances_curses.py
cp ../glances/glances/plugins/glances_processlist.py ./backup/glances/plugins/glances_processlist.py
cp ../glances/glances/plugins/glances_help.py ./backup/glances/plugins/glances_help.py  