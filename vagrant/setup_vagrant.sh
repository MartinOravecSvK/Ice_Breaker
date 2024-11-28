sudo apt-get update -y

sudo apt install -y python3-pip python3-dev build-essential gdb gcc-multilib nasm cmake
sudo apt install -y zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev wget libbz2-dev graphviz

cd workspace
# install python3.10
cd Python-3.10.13
sudo make install
cd ..
#install ROPgadget
cd ROPgadget-master
sudo -H python3 -m pip install ROPgadget
cd ..
#install netcat
cd netcat-0.7.1
./configure
make
cp src/netcat /tmp/nc
cd

pip3 install --upgrade pip
pip3 install capstone psutil setuptools angr cfg-explorer angr-utils