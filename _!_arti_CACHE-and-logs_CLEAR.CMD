
del /q %USERPROFILE%\AppData\Local\torproject\Arti\cache\dir_blobs\*
del /q %USERPROFILE%\AppData\Local\torproject\Arti\cache\*

del /q cache\dir_blobs\*
del /q cache\*

copy /A /V /Y pt_state\lyrebird1-32\lyrebird.log lyrebird1.log.BAK
copy /A /V /Y pt_state\lyrebird1-64\lyrebird.log lyrebird1.log.BAK

copy /A /V /Y pt_state\lyrebird2-32\lyrebird.log lyrebird2.log.BAK
copy /A /V /Y pt_state\lyrebird2-64\lyrebird.log lyrebird2.log.BAK

copy /A /V /Y pt_state\obfs4proxy-32\obfs4proxy.log obfs4proxy.log.BAK
copy /A /V /Y pt_state\obfs4proxy-64\obfs4proxy.log obfs4proxy.log.BAK

del /q pt_state\lyrebird1-32\lyrebird.log
del /q pt_state\lyrebird1-64\lyrebird.log

del /q pt_state\lyrebird2-32\lyrebird.log
del /q pt_state\lyrebird2-64\lyrebird.log

del /q pt_state\obfs4proxy-32\obfs4proxy.log
del /q pt_state\obfs4proxy-64\obfs4proxy.log

copy /A /V /Y snowflake.log snowflake.log.BAK
del /q snowflake.log

rmdir /S /Q cache

rmdir /S /Q pt_state
