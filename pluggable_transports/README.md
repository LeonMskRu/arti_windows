
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
