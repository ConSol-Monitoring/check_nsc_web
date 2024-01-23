FROM golang:1.21.6-alpine  

RUN apk add --update --no-cache build-base make bash git && rm -rf /var/cache/apk/*
#RUN apt-get install -yq git-core make
RUN mkdir -p /go/src/app
RUN git config --global --add safe.directory /go/src/app
VOLUME /go/src/app
WORKDIR /go/src/app

CMD ["make"]
