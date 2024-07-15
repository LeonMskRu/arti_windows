
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

Bridges FallBackDir берутся из Directories в Tor Control Panel

---

Bridges RU-only == +Stable -Exit\
рабочие на момент upload с Ростелеком/Калуга с IPv6 (не teredo)
