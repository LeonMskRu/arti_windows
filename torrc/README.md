
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

Bridges RU-only == IPv4+IPv6. IPv4 при блокировке/бане могут и отсутствовать.\
+Stable -Exit

---

страны выбраны в том числе по кол-ву Guard
![Tor Control Panel](https://imagizer.imageshack.com/a/img924/3555/tYAfLx.png)
