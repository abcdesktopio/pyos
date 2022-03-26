#!/bin/bash

# Linux: Linux
# Mac: Darwin
# Windows: Windows
# call from pyos
# command = 'oc/auth/ntlm/ntlm_auth.' + platform.system() 

# on mac os X
# brew install pkg-config
# brew install ntlmlib
# brew install libntlm
# brew install glib


platform="unknown"
case "$OSTYPE" in
  darwin*)  platform="Darwin" ;; 
  linux*)   platform="Linux" ;;
  bsd*)     platform="bsd" ;;
  msys*)    platform="Windows" ;;
  *)        echo "unknown: $OSTYPE" ;;
esac

# on Unix system 
# both MacOS/X and Linux
gcc -o ntlm_auth rc4.c ntlm_auth_v2.c -DPASSWORD=pwd -DUSERNAME=who -DDOMAIN=which $(pkg-config --cflags --libs glib-2.0)
strip ntlm_auth
mv ntlm_auth ntlm_auth.$platform
