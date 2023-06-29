all: version

version:
	$(shell ./mkversion.sh)

flake:
	flake8 --ignore=E1,E2,E3,W1,W2,E501 .

install:
	pip3 install -r requirements.txt --upgrade

