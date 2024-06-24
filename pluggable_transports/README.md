
собрано на windows10 64bit\
работа на 32bit и win7/8/etc не проверялась.

если не работают транспорты из сборки\
x86_64 == client-64.exe или i686(386) == client-32.exe\
то файлы obfs4 (lyrebird), snowflake, webtunnel\
можно взять в [Tor Expert Bundle](https://www.torproject.org/download/tor/)
или [TOR browser](https://dist.torproject.org/torbrowser/)

---

go get -u

env GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -a -v -o client-64.exe

env GOOS=windows GOARCH=386 CGO_ENABLED=0 go build -ldflags="-s -w" -a -v -o client-32.exe


---

убрал один вариант snowflake

curl: (60) SSL: no alternative certificate subject name matches target host name 'snowflake-broker.torproject.net.global.prod.fastly.net'
More details here: https://curl.se/docs/sslcerts.html
curl failed to verify the legitimacy of the server and therefore could notestablish a secure connection to it. To learn more about this situation and how to fix it, please visit the web page mentioned above.
