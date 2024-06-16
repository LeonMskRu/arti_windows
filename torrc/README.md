
добавить можно как в сам torrc\
так и через %include c:\\tor\\bridges_IPv6.conf 

---

~~FallBackDir берутся из "auto select relays" Directories в Tor Control Panel~~

FallBackDir == ru,us,ca,de\
+HSDir +Stable -Exit -Guard\
на данный момент проверки работы нет. просто список

---

Bridges IPv6 == nl fr fi lu se gb ch ro no cz ru bg dk it is es at hu gr be ie hr pt\
+Guard +Fast +Stable -Exit -HSDir
рабочие на момент сканирования/выкладывния с Ростелеком/Калуга с IPv6 (не teredo)

---

Bridges RU-only == IPv4+IPv6. IPv4 при блокировке/бане могут и отсутствовать.
+Stable -Exit

---

страны выбраны в том числе по кол-ву Guard
![image](https://github.com/LeonMskRu/arti_windows/assets/67465011/9546c60f-8c95-4020-8778-4453fe8a6017)
