
c:\cygwin\bin\grep.exe ERROR pt_state\lyrebird1-32\lyrebird.log | c:\cygwin\bin\sort.exe -k 4 | c:\cygwin\bin\gawk.exe '{print $2 $3 $4}' >> .error_obfs4.log
c:\cygwin\bin\grep.exe ERROR pt_state\lyrebird1-64\lyrebird.log | c:\cygwin\bin\sort.exe -k 4 | c:\cygwin\bin\gawk.exe '{print $2 $3 $4}' >> .error_obfs4.log

c:\cygwin\bin\grep.exe ERROR pt_state\lyrebird2-32\lyrebird.log | c:\cygwin\bin\sort.exe -k 4 | c:\cygwin\bin\gawk.exe '{print $2 $3 $4}' >> .error_obfs4.log
c:\cygwin\bin\grep.exe ERROR pt_state\lyrebird2-64\lyrebird.log | c:\cygwin\bin\sort.exe -k 4 | c:\cygwin\bin\gawk.exe '{print $2 $3 $4}' >> .error_obfs4.log

c:\cygwin\bin\grep.exe ERROR pt_state\obfs4proxy-32\obfs4proxy.log | c:\cygwin\bin\sort.exe -k 4 | c:\cygwin\bin\gawk.exe '{print $2 $3 $4}' >> .error_obfs4.log
c:\cygwin\bin\grep.exe ERROR pt_state\obfs4proxy-64\obfs4proxy.log | c:\cygwin\bin\sort.exe -k 4 | c:\cygwin\bin\gawk.exe '{print $2 $3 $4}' >> .error_obfs4.log

c:\cygwin\bin\grep.exe ERROR pt_state\lyrebird1-32\lyrebird.log | c:\cygwin\bin\sort.exe -k 4 | c:\cygwin\bin\gawk.exe '{print $2 $3 $4}'
c:\cygwin\bin\grep.exe ERROR pt_state\lyrebird1-64\lyrebird.log | c:\cygwin\bin\sort.exe -k 4 | c:\cygwin\bin\gawk.exe '{print $2 $3 $4}'

c:\cygwin\bin\grep.exe ERROR pt_state\lyrebird2-32\lyrebird.log | c:\cygwin\bin\sort.exe -k 4 | c:\cygwin\bin\gawk.exe '{print $2 $3 $4}'
c:\cygwin\bin\grep.exe ERROR pt_state\lyrebird2-64\lyrebird.log | c:\cygwin\bin\sort.exe -k 4 | c:\cygwin\bin\gawk.exe '{print $2 $3 $4}'

c:\cygwin\bin\grep.exe ERROR pt_state\obfs4proxy-32\obfs4proxy.log | c:\cygwin\bin\sort.exe -k 4 | c:\cygwin\bin\gawk.exe '{print $2 $3 $4}'
c:\cygwin\bin\grep.exe ERROR pt_state\obfs4proxy-64\obfs4proxy.log | c:\cygwin\bin\sort.exe -k 4 | c:\cygwin\bin\gawk.exe '{print $2 $3 $4}'

pause
