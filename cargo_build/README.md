**на [releases](https://github.com/LeonMskRu/arti_windows/releases) может быть более новая версия**

добавлены _release и arti-1.2.3-release.exe\
env LDFLAGS="-static -all-static" RUSTFLAGS="-Ctarget-cpu=native -Awarnings" c:\cygwin\bin\time.exe\
 cargo build --release --no-default-features --features static-sqlite,rustls,bridge-client,compression,dns-proxy,harden,onion-service-client,pt-client,tokio,vanguards,tor-circmgr/ntor_v3 --timings
 
---

собрано на windows10 64bit\
~~(для x86_64-gnu поменял mingw64 на ucrt64).~~\
работа на 32bit и win7/8/etc не проверялась.

---

x86_64-msvc == RUSTFLAGS="-C target-cpu=native"\
.diff_cpu_native.conf

[profile.release]\
strip = true\
codegen-units = 1\
lto = true\
opt-level = "z"\
panic = "abort"\
debug = false\
incremental = true

---

cargo update (зависимости и обновления) делается только для ARTI.EXE 

+ arti-1.2.3-x86_64-gnu.exe arti-1.2.3-i686-gnu.exe == Rustls
+ arti-1.2.3-x86_64-msvc.exe arti-1.2.3-i686-msvc.exe == NativeTls

 ---

cargo update (зависимости и обновления) для всего. даже то что не компилится и не выкладывается. (shadow/etc)

+ arti-testing.exe
+ connection-checker.exe
+ obfs4-checker.exe
+ arti.exe

x86_64-gnu / x86_64-msvc / i686-gnu / i686-msvc == NativeTls

 ---

cargo build^
 --target i686-pc-windows-gnu^ --release^ -p arti^\
 --no-default-features^\
 --features static-sqlite,rustls,bridge-client,compression,dns-proxy,harden,onion-service-client,pt-client,tokio,vanguards

cargo build^
 --target x86_64-pc-windows-gnu^ --release^ -p arti^\
 --no-default-features^\
 --features static-sqlite,rustls,bridge-client,compression,dns-proxy,harden,onion-service-client,pt-client,tokio,vanguards

cargo build^
 --target i686-pc-windows-msvc^ --release^ -p arti^\
 --features static

cargo build^
 --target x86_64-pc-windows-msvc^ --release^ -p arti^\
 --features static

 ---

cargo build^
 --target x86_64-pc-windows-gnu^ --release^ -p arti -p connection-checker -p obfs4-checker -p arti-testing^\
 --features static

cargo build^
 --target i686-pc-windows-gnu^ --release^ -p arti -p connection-checker -p obfs4-checker -p arti-testing^\
 --features static

cargo build^
 --target x86_64-pc-windows-msvc^ --release^  -p arti -p connection-checker -p obfs4-checker -p arti-testing^\
 --features static

cargo build^
 --target i686-pc-windows-msvc^ --release^ -p arti -p connection-checker -p obfs4-checker -p arti-testing^\
 --features static

windows:utf-8-BOM
