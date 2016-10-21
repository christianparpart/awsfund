all: awsfund

awsfund: main.go
	go build

install:
	go install

clean:
	rm -f awsfund

.PHONY: clean all install
