FROM kazuho/h2o-ci:ubuntu1904

USER root
WORKDIR /

RUN apt-get update && \
  apt-get install -y net-tools iputils-ping tcpdump ethtool iperf

RUN cd /

# quicly
RUN git clone https://github.com/h2o/quicly.git

# build with --build-arg CACHEBUST=$(date +%s)
ARG CACHEBUST=1

RUN cd quicly &&  git pull && git submodule update --init --recursive && cmake . && make
COPY server.key quicly
COPY server.crt quicly

# setup and endpoint
COPY setup.sh .
RUN chmod +x setup.sh

COPY run_endpoint.sh .
RUN chmod +x run_endpoint.sh

RUN wget https://raw.githubusercontent.com/vishnubob/wait-for-it/master/wait-for-it.sh && chmod +x wait-for-it.sh

ENTRYPOINT [ "./run_endpoint.sh" ]
