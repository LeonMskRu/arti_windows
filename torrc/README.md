
добавить можно как в сам torrc\
так и через %include c:\\tor\\bridges_IPv6.conf 

для поиска relay работающих "как мосты" (vanilla bridge)\
и доступных на вашем провайдере есть\
 ~~[tor-relay-scanner на python](https://github.com/wildekat/tor-relay-scanner)~~
или [tor-relay-scanner на GO](https://github.com/juev/tor-relay-scanner-go)
в этих fork добавлено
+ -4 scan IPv4 addresses
+ -6 scan IPv6 addresses

---

~~FallBackDir берутся из "auto select relays" Directories в Tor Control Panel~~\
Bridges FallBackDir берутся из Directories в Tor Control Panel
[Исключать недоступные по IPv4](https://imagizer.imageshack.com/a/img924/8307/ZVhpUt.png)

---

LIST FallBackDir == RU,US,DE +V2Dir +HSDir +Stable -Exit -Guard\
на данный момент проверки работы нет. просто список

---

Bridges IPv6 == nl fr fi lu se gb ch ro no cz ru bg dk it is es at hu gr be ie hr pt\
+Guard +Fast +Stable -Exit\
рабочие на момент upload с Ростелеком/Калуга с IPv6 (не teredo)

---

Bridges RU-only == IPv4 при блокировке/бане могут и отсутствовать.\
+Stable -Exit\
рабочие на момент upload с Ростелеком/Калуга с IPv6 (не teredo)

---

страны выбраны в том числе по кол-ву Guard

![Tor Control Panel](https://imagizer.imageshack.com/a/img924/6849/zJkJOo.png)
