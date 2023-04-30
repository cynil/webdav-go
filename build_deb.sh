go build main.go
mv main ./build/usr/bin/webdav
dpkg -b webdav_4.2.1_amd64.deb