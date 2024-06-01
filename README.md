https://github.com/LeonMskRu/arti_windows/releases
ARTI (tor)

собрано на windows10 64bit

работа на 32 и win7 не проверялась

https://rutracker.org/forum/viewtopic.php?t=6360120&start=60
https://ntc.party/t/%D0%BE%D0%B1%D1%81%D1%83%D0%B6%D0%B4%D0%B5%D0%BD%D0%B8%D0%B5-tor-arti-rust-%D0%B2%D0%B5%D1%80%D1%81%D0%B8%D1%8F/4912/65

для рабочих мостов есть https://github.com/ValdikSS/tor-relay-scanner

если есть IPv6 имейте ввиду https://github.com/ValdikSS/tor-relay-scanner/issues/13

хотя АРТИ вообще странно с мостами работает.

лучше экспортировать из Tor Control Panel “relays - guard” https://i.imgur.com/M7sNVjB.gif

snowflake конфиг править под себя

это разные “сервера”. могут и все 4е не работать на части провайдеров.

Azure, CDN77, AMP cache, fastly sstatic

!!! ОБЯЗАТЕЛЬНО УДАЛЯТЬ %USERPROFILE%\AppData\Local\torproject\Arti\data\state*.json !!!

arti-1.2.3-x86_64-gnu.exe using runtime: Rustls

arti-1.2.3-i686-gnu.exe using runtime: Rustls

arti-1.2.3-release.exe using runtime: Rustls

arti-1.2.3-x86_64-msvc.exe using runtime: NativeTls

arti-1.2.3-i686-msvc.exe using runtime: NativeTls

arti-bench.exe
arti-testing.exe
arti.exe
connection-checker.exe
dns-resolver.exe
download-manager.exe
fixup-features.exe
hyper-http-client-example.exe
hyper-http-hs-example.exe
obfs4-checker.exe
pt-proxy.exe
