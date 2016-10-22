FROM golang:1.7.3-alpine
MAINTAINER Christian Parpart <trapni@gmail.com>

ADD . /go/src/github.com/christianparpart/awsfund
RUN cd /go/src/github.com/christianparpart/awsfund && go install

ENTRYPOINT ["/go/bin/awsfund"]
CMD ["--help"]
