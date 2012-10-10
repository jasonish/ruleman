.PHONY: build

all:

build:
	python setup.py build

install:
	python setup.py install

test:
	python lib/ruleman/test.py

clean:
	rm -rf build
	find . -name \*.pyc | xargs rm -f
	find . -name \*~ | xargs rm -f
	rm -f lib/ruleman/_buildtime.py
