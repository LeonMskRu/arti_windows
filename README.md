# ARTI (tor) Windows сборки

+ [rutracker.org](https://rutracker.org/forum/viewtopic.php?t=6360120 "форум")
+ [ntc.party](https://ntc.party/t/%D0%BE%D0%B1%D1%81%D1%83%D0%B6%D0%B4%D0%B5%D0%BD%D0%B8%D0%B5-tor-arti-rust-%D0%B2%D0%B5%D1%80%D1%81%D0%B8%D1%8F/4912 "антизапрет")

<!--TODO ARTI-->
## TODO ARTI

- [x] транспорты для мостов :+1:
- [ ] корректная работа с мостами в целом. :cursing_face:
- [ ] неглючное соединение с списками из 10-20 и больше мостов :man_facepalming:
- [ ] GeoIP (есть в коде. нет в конфиге.) :thumbsdown:
- [ ] настройки в конфиге IPv4/IPv6
- [ ] не только режим socks-proxy но и HTTPTunnelPort

<!--Сборка Build-->
## Сборка Build

собрано на windows10 64bit\
~~(для x86_64-gnu поменял mingw64 на ucrt64).~~\
работа на 32bit и win7/8/etc не проверялась.

если не работают транспорты из сборки\
x86_64 == client-64.exe или i686(386) == client-32.exe\
то файлы obfs4 (lyrebird), snowflake, webtunnel\
можно взять в [Tor Expert Bundle](https://www.torproject.org/download/tor/)
или [TOR browser](https://dist.torproject.org/torbrowser/)

<!--Мосты Bridges-->
## Мосты Bridges

 **!!! НА ДАННЫЙ МОМЕНТ\
 при кол-ве мостов 10+ уже начинаются глюки и тормоза.\
 ~~20+ вообще баги лезут.~~**

для поиска relay работающих "как мосты" (vanilla bridge)\
и доступных на вашем провайдере есть\
 [tor-relay-scanner на python](https://github.com/wildekat/tor-relay-scanner)
или [tor-relay-scanner на GO](https://github.com/juev/tor-relay-scanner-go)
в этих fork добавлено
+ -4 scan IPv4 addresses
+ -6 scan IPv6 addresses

мосты так же можно экспортировать из [Tor Control Panel](https://github.com/abysshint/tor-control-panel "github")
“relays-guard” [imgur .gif](https://i.imgur.com/M7sNVjB.gif)

snowflake конфиг править под себя.\
это разные “сервера”.\
могут и все 4е не работать на части провайдеров.\
Azure, CDN77, AMP cache, fastly sstatic

мосты obfs4/webtunnel и тем более _BRIDGES только для теста и могут уже не работать

 **!!! ОБЯЗАТЕЛЬНО УДАЛЯТЬ руками или\
 _!_arti_state_CLEAR.CMD**
+ или %USERPROFILE%\AppData\Local\torproject\Arti\data\state\
+ или state\ в папке программы


 **При проблемах использования мостов/bridges нужно удалить самому или\
 _!_arti_CACHE-and-logs_CLEAR.CMD**
+ или %USERPROFILE%\AppData\Local\torproject\Arti\cache\
+ или cache\ в папке программы

<!--старые Windows (не 10/11)-->
## старые Windows (не 10/11)

**может быть придется ставить UCRT для Windows7/8/etc**
[support.microsoft.com](https://support.microsoft.com/ru-ru/topic/%D0%BE%D0%B1%D0%BD%D0%BE%D0%B2%D0%BB%D0%B5%D0%BD%D0%B8%D0%B5-%D0%B4%D0%BB%D1%8F-%D1%83%D0%BD%D0%B8%D0%B2%D0%B5%D1%80%D1%81%D0%B0%D0%BB%D1%8C%D0%BD%D0%BE%D0%B9-%D1%81%D1%80%D0%B5%D0%B4%D1%8B-%D0%B2%D1%8B%D0%BF%D0%BE%D0%BB%D0%BD%D0%B5%D0%BD%D0%B8%D1%8F-c-%D0%B2-windows-c0514201-7fe6-95a3-b0a5-287930f3560c)
