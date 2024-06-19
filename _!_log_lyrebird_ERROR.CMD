
c:\cygwin\bin\grep.exe ERROR pt_state\lyrebird-32\lyrebird.log | c:\cygwin\bin\sort.exe -k 4 | c:\cygwin\bin\gawk.exe '{print $2 $3 $4}' > .error_obfs4.log
c:\cygwin\bin\grep.exe ERROR pt_state\lyrebird-64\lyrebird.log | c:\cygwin\bin\sort.exe -k 4 | c:\cygwin\bin\gawk.exe '{print $2 $3 $4}' > .error_obfs4.log

c:\cygwin\bin\grep.exe ERROR pt_state\lyrebird-32\lyrebird.log | c:\cygwin\bin\sort.exe -k 4 | c:\cygwin\bin\gawk.exe '{print $2 $3 $4}'
c:\cygwin\bin\grep.exe ERROR pt_state\lyrebird-64\lyrebird.log | c:\cygwin\bin\sort.exe -k 4 | c:\cygwin\bin\gawk.exe '{print $2 $3 $4}'

pause
