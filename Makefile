all: version

version:
	$(shell ./mkversion.sh)

flake:
	flake8 --ignore=E1,E2,E3,W1,W2,E501 .

vulture:
	vulture . --min-confidence 100 --exclude pan

install:
	pip3 install -r requirements.txt --upgrade
