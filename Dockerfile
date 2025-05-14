FROM python:3
WORKDIR /var/pyos
# install dev lib 
RUN apt-get update && apt-get install -y --no-install-recommends \
	wget \
	libffi-dev   \
	libkrb5-dev  \
        libsasl2-dev \ 
        libsasl2-dev \
        libldap2-dev \
	libgeoip-dev \
        libssl-dev   \
        libgssapi-krb5-2 \
	rustc  

#  install kerberos libgss ldap
RUN  apt-get update && apt-get install -y  --no-install-recommends  \
	cntlm 			\
	sasl2-bin 		\
	libsasl2-2 		\
	libsasl2-modules 	\
	libsasl2-modules-gssapi-mit	\
        krb5-user               \
	krb5-config		\
 	libnss3-tools           \
        ldap-utils              \
	libgssglue1		\
	libgssrpc4		\
	libgss3			\
        libgssapi-krb5-2        \
        libgssglue1		\
	libnss3-tools	 	\
	gss-ntlmssp		\
    && apt-get clean            \
    && rm -rf /var/lib/apt/lists/*

# GeoLite2
RUN mkdir -p /usr/share/geolite2 && \
    wget https://git.io/GeoLite2-ASN.mmdb -P /usr/share/geolite2 && \
    wget https://git.io/GeoLite2-City.mmdb -P /usr/share/geolite2

# install ntlm_auth
COPY --from=ghcr.io/abcdesktopio/ntlm_auth:debian.bookworm /dist/*.deb /tmp
RUN apt-get update && \
    apt-get install -y  --no-install-recommends /tmp/*.deb && \
    apt-get clean  && \
    rm -rf /var/lib/apt/lists/* 
RUN echo /usr/lib/x86_64-linux-gnu/samba >> /etc/ld.so.conf.d/x86_64-linux-gnu.conf && /usr/sbin/ldconfig

# install pyos
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# copy ntlm_auth to oc/auth/ntlm/ntlm_auth
RUN  cp /usr/bin/ntlm_auth /var/pyos/oc/auth/ntlm/ntlm_auth
# create log directory
RUN mkdir -p /var/pyos/logs
CMD [ "./od.py" ]
