language: c

addons:
    apt:
      packages:
        - devscripts
        - fakeroot
        - debhelper

install:
    - git clone --depth 1 https://github.com/plusvic/yara.git yara3
    - cd yara3
    - bash ./build.sh
    - ./configure
    - make
    - cp ./yara ../php-malware-finder/
    - cd ..

script:
    - make tests
    - make deb
