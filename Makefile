##
## Example Makefile for AdvSecSysEng Lab1
##
# The submission archive will be extracted in /home/unprivileged and make will
# be invoked with these targets as user 'unprivileged' from this directory.
##
# Targets for vulnerable programs in the category A 'Stack Based Buffer Overflow'
#
# You need to implement at most one target per category
#
# Each implemented target must remove the 'NOT IMPLEMENTED' output, and produce
# an executable that has the same name as the target identifier.


GCC=/usr/bin/gcc

LEVEL_ENTRY = -fno-stack-protector -D_FORTIFY_SOURCE=0 -Wl,-z,norelro,-z,execstack -no-pie
LEVEL_MEDIUM = -fno-stack-protector -D_FORTIFY_SOURCE=0 -Wl,-z,relro -no-pie
LEVEL_ADVANCED = -fstack-protector-all -D_FORTIFY_SOURCE=0  -Wl,-z,relro,-z,now -fpie -pie

CLANG=/usr/bin/clang

LEVEL_ELITE = -fstack-protector-all -D_FORTIFY_SOURCE=2 -z relro -z now -fpie -pie -flto -fsanitize=cfi -fsanitize=safe-stack -fuse-ld=gold


CFLAGS = -m32 -g  -O0 -Xlinker -rpath=/home/jonas/asse/ASSE-Lab1
CFLAGS64 = -m64 -g -O0 # -static

# The grading robot will set the permissions of the vulnerable programs using the 'install' target.

vuln_programs =  vuln_stackoverflow-medium vuln_heapcorruption-entry

install: $(vuln_programs)
	$(foreach vuln_program, $(vuln_programs), [ -e $(vuln_program) ] && ( sudo chown privileged $(vuln_program) ) || true ;)
	$(foreach vuln_program, $(vuln_programs), [ -e $(vuln_program) ] && ( sudo chmod u+s $(vuln_program) ) || true ;)

# As an example, we have implemented the following target
vuln_stackoverflow-entry:
	@echo 'NOT IMPLEMENTED'

# Another example that shows a vulnerable program based on a real-world vulnerability
vuln_stackoverflow-medium: vuln_stackoverflow-medium.c
	$(GCC) $(CFLAGS) $(LEVEL_MEDIUM) -o $@ $<

vuln_stackoverflow-advanced:
	@echo 'NOT IMPLEMENTED'

vuln_stackoverflow-elite:
	@echo 'NOT IMPLEMENTED'


# Targets for vulnerable programs in the category B 'Format-String Vulnerabilities'
#
# You need to implement at most one target per category
#
# Each implemented target must remove the 'NOT IMPLEMENTED' output, and produce
# an executable that has the same name as the target identifier.

vuln_formatstring-entry:
	@echo 'NOT IMPLEMENTED'

vuln_formatstring-medium: 
	@echo 'NOT IMPLEMENTED'

vuln_formatstring-advanced:
	@echo 'NOT IMPLEMENTED'

vuln_formatstring-elite:
	@echo 'NOT IMPLEMENTED'



# Targets for vulnerable programs in the category C 'Heap Corruption'
#
# You need to implement at most one target per category
#
# Each implemented target must remove the 'NOT IMPLEMENTED' output, and produce
# an executable that has the same name as the target identifier.

vuln_heapcorruption-entry: vuln_heapcorruption-entry.c
	$(GCC) $(CFLAGS) $(LEVEL_ENTRY) -o $@ $<

dlmalloc/lib/libmalloc.a: dlmalloc
	$(MAKE) -C $<

dlmalloc: 
	git clone https://github.com/ennorehling/dlmalloc.git
	


vuln_heapcorruption-medium:
	@echo 'NOT IMPLEMENTED'

vuln_heapcorruption-advanced:
	@echo 'NOT IMPLEMENTED'

vuln_heapcorruption-elite:
	@echo 'NOT IMPLEMENTED'
	

# Implement, similarly, your chosen exploit targets
#

# As an example, we have implemented the following target
exploit_stackoverflow-entry: exploit_stackoverflow-entry.py vuln_stackoverflow-entry
	/bin/bash -c 'source /home/vagrant/python-venv/pwn3/bin/activate; \
	./exploit_stackoverflow-entry.py'

exploit_stackoverflow-medium: exploit_stackoverflow-entry.py vuln_stackoverflow-medium
	/bin/bash -c 'source /home/vagrant/python-venv/pwn3/bin/activate; \
	./exploit_stackoverflow-entry.py'

exploit_stackoverflow-advanced: vuln_stackoverflow-advanced
	@echo 'NOT IMPLEMENTED'

exploit_stackoverflow-elite: vuln_stackoverflow-elite
	@echo 'NOT IMPLEMENTED'

exploit_formatstring-entry: vuln_formatstring-entry
	@echo 'NOT IMPLEMENTED'

exploit_formatstring-medium: vuln_formatstring-medium
	@echo 'NOT IMPLEMENTED'

exploit_formatstring-advanced: vuln_formatstring-advanced
	@echo 'NOT IMPLEMENTED'

exploit_formatstring-elite: vuln_formatstring-elite
	@echo 'NOT IMPLEMENTED'

exploit_heapcorruption-entry: exploit_heapcorruption-entry.py vuln_heapcorruption-entry
	/bin/bash -c 'source /home/vagrant/python-venv/pwn3/bin/activate; \
	./exploit_heapcorruption-entry.py'

exploit_heapcorruption-medium: vuln_heapcorruption-medium
	@echo 'NOT IMPLEMENTED'

exploit_heapcorruption-advanced: vuln_heapcorruption-advanced
	@echo 'NOT IMPLEMENTED'

exploit_heapcorruption-elite: vuln_heapcorruption-elite
	@echo 'NOT IMPLEMENTED'

