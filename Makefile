all:

build:
	python setup.py build

install:
	python setup.py install

clean:
	rm -rf build
	find . -name \*.pyc | xargs rm -f
	rm -f lib/ruleman/_buildtime.py
