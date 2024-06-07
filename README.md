собрано на windows10 64bit.
работа на 32bit и win7 не проверялась.

рабочие файлы транспортов obfs4 (lyrebird), snowflake, webtunnel можно взять в https://www.torproject.org/download/tor/ или https://dist.torproject.org/torbrowser/

https://rutracker.org/forum/viewtopic.php?t=6360120&start=60
https://ntc.party/t/%D0%BE%D0%B1%D1%81%D1%83%D0%B6%D0%B4%D0%B5%D0%BD%D0%B8%D0%B5-tor-arti-rust-%D0%B2%D0%B5%D1%80%D1%81%D0%B8%D1%8F/4912/65

для рабочих мостов есть https://github.com/ValdikSS/tor-relay-scanner
если есть IPv6 имейте ввиду https://github.com/ValdikSS/tor-relay-scanner/issues/13
хотя АРТИ вообще странно с мостами работает. лучше экспортировать из Tor Control Panel “relays - guard” https://i.imgur.com/M7sNVjB.gif

snowflake конфиг править под себя.
это разные “сервера”. могут и все 4е не работать на части провайдеров.
Azure, CDN77, AMP cache, fastly sstatic

!!! ОБЯЗАТЕЛЬНО УДАЛЯТЬ !!!
или %USERPROFILE%\AppData\Local\torproject\Arti\data\state*.json
или data\state*.json в папке программы

При проблемах использования мостов/bridges возможно понадобиться удалить %USERPROFILE%\AppData\Local\torproject\Arti\cache\

arti-1.2.3-x86_64-gnu.exe arti-1.2.3-i686-gnu.exe == Rustls

arti-1.2.3-x86_64-msvc.exe arti-1.2.3-i686-msvc.exe == NativeTls

arti-testing.exe
connection-checker.exe
obfs4-checker.exe

x86_64-gnu / x86_64-msvc / i686-gnu / i686-msvc == NativeTls
