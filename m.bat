REM  m.bat | $CMakeCurrentTargetName$ | $ProjectFileDir$
adb push outputs\arm64-v8a\%1 /data/local/tmp
adb shell su -c chmod +x /data/local/tmp/%1
adb shell su -c '/data/local/tmp/%1'
