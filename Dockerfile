FROM golang:latest

RUN apt update
RUN apt install -y libnss3-tools default-jre super

RUN mkdir -p /root/.pki/nssdb
RUN certutil -d /root/.pki/nssdb -N --empty-password

RUN cd /tmp && curl -JLO "https://dl.filippo.io/mkcert/latest?for=linux/amd64"
RUN cd /tmp && chmod +x mkcert-v*-linux-amd64 && cp mkcert-v*-linux-amd64 /usr/local/bin/mkcert

RUN cd /tmp && curl -L https://github.com/bmizerany/roundup/tarball/HEAD | tar xvzf -
RUN cd /tmp/*-roundup-* && ./configure && make && make install

WORKDIR /mkcert
COPY . .

RUN go mod download && go mod verify

ENV JAVA_HOME="/usr/lib/jvm/default-java"

CMD test/run
