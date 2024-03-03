FROM ubuntu:22.04

# tools
RUN apt-get -y update \
    && apt-get install -y init systemd \
    && apt-get install -y net-tools iputils-ping curl wget telnet less vim sudo \
    && apt-get install -y tzdata locales && locale-gen ja_JP.UTF-8 

RUN apt-get install -y lsb-release gnupg

# JP対応
ENV TZ Asia/Tokyo
ENV LANG ja_JP.UTF-8
ENV LANGUAGE ja_JP:ja

COPY systemd/nodex.service /etc/systemd/system/nodex.service
COPY systemd/test.env /etc/sysconfig/nodex.env
COPY nodex-agent /usr/sbin/nodex-agent
RUN chmod +x /usr/sbin/nodex-agent

# Configure nodex-agent to start automatically
RUN ln -s /etc/systemd/system/nodex.service /etc/systemd/system/multi-user.target.wants/nodex.service

CMD ["/sbin/init"]
