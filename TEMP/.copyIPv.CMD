
for %%I in (AS*.txt) do copy /B /V /Y %%~nxI %%~nxI.ipv4

for %%I in (AS*.txt) do copy /B /V /Y %%~nxI %%~nxI.ipv6
