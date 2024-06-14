https://rutracker.org/forum/viewtopic.php?t=6360120&start=60
https://ntc.party/t/%D0%BE%D0%B1%D1%81%D1%83%D0%B6%D0%B4%D0%B5%D0%BD%D0%B8%D0%B5-tor-arti-rust-%D0%B2%D0%B5%D1%80%D1%81%D0%B8%D1%8F/4912/65

собрано на windows10 64bit (для x86_64-gnu поменял mingw64 на ucrt64).
работа на 32bit и win7 не проверялась.

если не работают транспорты из сборки
x86_64 == -64.exe или i686(386) == -32.exe
то рабочие файлы obfs4 (lyrebird), snowflake, webtunnel
можно взять в https://www.torproject.org/download/tor/
или https://dist.torproject.org/torbrowser/

для мостов доступных на вашем провайдере есть fork https://github.com/wildekat/tor-relay-scanner
 добавлено
-4 --ipv4-only scan IPv4 addresses
-6 --ipv6-only scan IPv6 addresses

обычные еще можно экспортировать из Tor Control Panel “relays - guard” https://i.imgur.com/M7sNVjB.gif

snowflake конфиг править под себя.
это разные “сервера”. могут и все 4е не работать на части провайдеров.
Azure, CDN77, AMP cache, fastly sstatic

мосты obfs4/webtunnel и тем более _BRIDGES только для теста и могут уже не работать

!!! ОБЯЗАТЕЛЬНО УДАЛЯТЬ !!!
или %USERPROFILE%\AppData\Local\torproject\Arti\data\state*.json
или data\state*.json в папке программы
 _!_arti_state_CLEAR.CMD

При проблемах использования мостов/bridges возможно понадобиться удалить
или %USERPROFILE%\AppData\Local\torproject\Arti\cache\*
или cache\* в папке программы
 _!_arti_CACHE-and-logs_CLEAR.CMD

 ===

может быть придется ставить UCRT для Windows7/8/etc
https://support.microsoft.com/ru-ru/topic/%D0%BE%D0%B1%D0%BD%D0%BE%D0%B2%D0%BB%D0%B5%D0%BD%D0%B8%D0%B5-%D0%B4%D0%BB%D1%8F-%D1%83%D0%BD%D0%B8%D0%B2%D0%B5%D1%80%D1%81%D0%B0%D0%BB%D1%8C%D0%BD%D0%BE%D0%B9-%D1%81%D1%80%D0%B5%D0%B4%D1%8B-%D0%B2%D1%8B%D0%BF%D0%BE%D0%BB%D0%BD%D0%B5%D0%BD%D0%B8%D1%8F-c-%D0%B2-windows-c0514201-7fe6-95a3-b0a5-287930f3560c
