
del /q %USERPROFILE%\AppData\Local\torproject\Arti\cache\dir_blobs\*
del /q %USERPROFILE%\AppData\Local\torproject\Arti\cache\*

del /q cache\dir_blobs\*
del /q cache\*

copy /A /V /Y pt_state\lyrebird\lyrebird.log lyrebird.log.BAK
del /q pt_state\lyrebird\lyrebird.log

copy /A /V /Y snowflake.log snowflake.log.BAK
del /q snowflake.log

rmdir /S /Q cache

rmdir /S /Q pt_state
