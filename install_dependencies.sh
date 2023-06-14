sudo apt install -y astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind
sudo apt install -y build-essential git cmake python3 libssl-dev

echo "Installing liboqs..."
rm -rf liboqs
git clone -b main https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja -DCMAKE_BUILD_TYPE=Release ..
ninja
sudo ninja install
cd ../..

sudo apt-get install -y redis-server

echo "Installing RedisClient..."
rm -rf redisclient
git clone https://github.com/nekipelov/redisclient.git

echo "Installing hiredis..."
rm -rf hiredis
git clone https://github.com/redis/hiredis.git
cd hiredis
make -j$(nproc)
sudo make install
cd ..

echo "Installing redis-plus-plus..."
rm -rf redis-plus-plus
git clone https://github.com/sewenew/redis-plus-plus.git
cd redis-plus-plus
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
sudo make install
cd ../..

echo "Done!"