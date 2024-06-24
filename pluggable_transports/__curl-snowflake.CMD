
echo Azure
echo.

curl -4 --http2 -I -v https://snowflake-broker.azureedge.net/ 
timeout /t 15
curl -4 --http2 -I -v https://ajax.aspnetcdn.com
timeout /t 15

echo.
echo CDN77
echo.

curl -4 --http2 -I -v https://1098762253.rsc.cdn77.org/ 
timeout /t 15
curl -4 --http2 -I -v https://docs.plesk.com
timeout /t 15
curl -4 --http2 -I -v https://www.phpmyadmin.net
timeout /t 15

echo.
echo AMP cache
echo.

curl -4 --http2 -I -v https://snowflake-broker.torproject.net/ 
timeout /t 15
curl -4 --http2 -I -v https://cdn.ampproject.org/ 
timeout /t 15
curl -4 --http2 -I -v https://www.google.com
timeout /t 15
