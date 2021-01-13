# COBRA_421_opt
personal COBRA SYSCALL11 optimized for 4.21 REBUG

- kernels prepatched with habib's syscall15 as syscall40. this does not scramble syscall table in ida
- network/socat debug output fully fixed, so now it works with prodg targetmanager/debugger side by side. big thanks to habib
- using syscall11 instead of syscall8, which makes cobra less 'fragile', so I have removed all of these cobra exceptions.
imho, this should have been done in first place, but well...
- removed all stealth and security features, since you cannot go online with 4.21
- added opcode for game plugins loading, same just like vsh plugin loading

credits to Joonie, habib, aldostools, NZV, RouletteBoi, Evilnat
