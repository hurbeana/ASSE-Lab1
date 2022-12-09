#!/bin/bash

tar -czf lab1_07.tgz \
	exploit_heapcorruption-entry.py \
	exploit_stackoverflow-medium.py \
	vuln_heapcorruption-entry.c \
	vuln_stackoverflow-medium.c \
	lab1_07.pdf \
	Makefile
