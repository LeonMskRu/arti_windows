cargo build^
 --target i686-pc-windows-gnu^
 --release^
 -p arti^
 --no-default-features^
 --features static-sqlite,rustls,bridge-client,compression,dns-proxy,harden,onion-service-client,pt-client,tokio,vanguards

cargo build^
 --target x86_64-pc-windows-gnu^
 --release^
 -p arti^
 --no-default-features^
 --features static-sqlite,rustls,bridge-client,compression,dns-proxy,harden,onion-service-client,pt-client,tokio,vanguards

cargo build^
 --target i686-pc-windows-msvc^
 --release^
 -p arti^
 --features static

cargo build^
 --target x86_64-pc-windows-msvc^
 --release^
 -p arti^
 --features static

 ===

cargo build^
 --release^
 --target x86_64-pc-windows-gnu^
 -p arti -p connection-checker -p obfs4-checker -p arti-testing^
 --features static

cargo build^
 --release^
 --target i686-pc-windows-gnu^
 -p arti -p connection-checker -p obfs4-checker -p arti-testing^
 --features static

cargo build^
 --release^
 --target x86_64-pc-windows-msvc^
 -p arti -p connection-checker -p obfs4-checker -p arti-testing^
 --features static

cargo build^
 --release^
 --target i686-pc-windows-msvc^
 -p arti -p connection-checker -p obfs4-checker -p arti-testing^
 --features static
