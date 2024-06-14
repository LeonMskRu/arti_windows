собрано на windows10 64bit (x86_64-gnu поменял mingw64 на ucrt64).
работа на 32bit и win7 не проверялась.

рабочие файлы транспортов obfs4 (lyrebird), snowflake, webtunnel
 можно взять в https://www.torproject.org/download/tor/
 или https://dist.torproject.org/torbrowser/

https://rutracker.org/forum/viewtopic.php?t=6360120&start=60
https://ntc.party/t/%D0%BE%D0%B1%D1%81%D1%83%D0%B6%D0%B4%D0%B5%D0%BD%D0%B8%D0%B5-tor-arti-rust-%D0%B2%D0%B5%D1%80%D1%81%D0%B8%D1%8F/4912/65

для рабочих мостов есть fork https://github.com/wildekat/tor-relay-scanner
 добавлено -4 --ipv4-only Only scan IPv4 addresses -6 --ipv6-only Only scan IPv6 addresses

хотя АРТИ вообще странно с мостами работает. лучше экспортировать из Tor Control Panel “relays - guard” https://i.imgur.com/M7sNVjB.gif

snowflake конфиг править под себя.
это разные “сервера”. могут и все 4е не работать на части провайдеров.
Azure, CDN77, AMP cache, fastly sstatic

!!! ОБЯЗАТЕЛЬНО УДАЛЯТЬ !!!
или %USERPROFILE%\AppData\Local\torproject\Arti\data\state*.json
или data\state*.json в папке программы

_!_arti_state_CLEAR.CMD

_!_arti_CACHE-and-logs_CLEAR.CMD

При проблемах использования мостов/bridges возможно понадобиться удалить
или %USERPROFILE%\AppData\Local\torproject\Arti\cache\
или cache\ в папке программы

 ===

cargo update (зависимости и обновления) делается только для ARTI.EXE 

arti-1.2.3-x86_64-gnu.exe arti-1.2.3-i686-gnu.exe == Rustls

arti-1.2.3-x86_64-msvc.exe arti-1.2.3-i686-msvc.exe == NativeTls

 ===

cargo update (зависимости и обновления) для всего. даже то что не компилится и не выкладывается. (shadow/etc)

arti-testing.exe
connection-checker.exe
obfs4-checker.exe
arti.exe

x86_64-gnu / x86_64-msvc / i686-gnu / i686-msvc == NativeTls
