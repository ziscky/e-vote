FROM ubuntu:latest
MAINTAINER Eric Mokaya <emagemvee@gmail.com>
RUN apt-get update \
    && apt-get install -y build-essential cmake git wget libncurses5-dev libreadline-dev nettle-dev libgnutls28-dev libuv1-dev  cython3 python3-dev libcppunit-dev libjsoncpp-dev libasio-dev libssl-dev libstdc++6 python3-setuptools \
    && apt-get clean\

    && wget https://github.com/msgpack/msgpack-c/releases/download/cpp-2.1.5/msgpack-2.1.5.tar.gz\
	&& tar -xzf msgpack-2.1.5.tar.gz\
	&& cd msgpack-2.1.5 && mkdir build && cd build\
	&& cmake -DMSGPACK_CXX11=ON -DMSGPACK_BUILD_EXAMPLES=OFF -DCMAKE_INSTALL_PREFIX=/usr ..\
	&& make -j8 && make install\
    && cd ../.. && rm -rf msgpack-2.1.5 msgpack-2.1.5.tar.gz\
    && cd /\

    && git clone https://github.com/msgpack/msgpack-c.git\
    && cd msgpack-c && cmake -DMSGPACK_CXX17=ON .\
    && make install\
    && cd /\

    && git clone https://github.com/weidai11/cryptopp.git\
    && cd cryptopp && make libcryptopp.so && make install\
    && cd /\

    && git clone https://github.com/ziscky/opendht.git\
	&& cd opendht && git checkout -b "nopackettimeout"\
	&& mkdir build && cd build\
	&& cmake .. -DCMAKE_INSTALL_PREFIX=/usr -DOPENDHT_PYTHON=Off -DOPENDHT_LTO=On && make -j8 && make install\
    && cd ../.. && rm -rf opendht\
    && cd /\

    && git clone https://github.com/ziscky/e-vote\
    && mkdir configs && cd e-vote && mkdir build && cd build\
    && cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_COMPILER=/usr/bin/g++ ..\
    && cd /e-vote/\
    && cmake --build build --target install -- -j 4

WORKDIR /e-vote/
ENTRYPOINT ["/e-vote/peer","/configs/conf.json","/configs/id.json","/configs/nodes.json"]
