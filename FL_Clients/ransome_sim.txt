@echo off
for /l %%x in (1,1,35) do echo Encrypted_Payload > locked_file_%%x.tmp
del locked_file_*.tmp