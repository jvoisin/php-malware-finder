VERSION=1.0
DEBVER := $(shell sed 's,[/\.].*,,' < /etc/debian_version)

tests:
	@cd ./php-malware-finder && bash ./tests.sh

debclean:
	rm -rf php-malware-finder/debian
	rm -f *.build *.changes *.deb

extract:
	cp -r debian php-malware-finder
	git checkout php-malware-finder/php.yar

rpm:
	@echo "no rpm build target for now, feel free to submit one"

deb: debclean extract 
	cd php-malware-finder && debuild -b -us -uc --lintian-opts -X po-debconf --profile debian
