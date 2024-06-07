
del /q %USERPROFILE%\AppData\Local\torproject\Arti\cache\dir_blobs\*
del /q %USERPROFILE%\AppData\Local\torproject\Arti\cache\*

del /q %USERPROFILE%\AppData\Local\torproject\Arti\data\state\*

del /q state\*.lock
del /q state\*.json

copy /A /V /Y pt_state\lyrebird\lyrebird.log lyrebird.log.BAK
del /q pt_state\lyrebird\lyrebird.log

copy /A /V /Y snowflake.log snowflake.log.BAK
del /q snowflake.log
