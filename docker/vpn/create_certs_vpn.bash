#!/bin/bash

# Default Vars
VERSION="0.0.2"
TYPE=""
LEN_RSA=""
LEN_AES=""
SET_NAME=""
USR_NAME=""
DAYS_VALID=""
FORCE_YES="0"
CFG_SERVER="0"
CFG_CLIENT="0"
CFG_PORT_BRIDGE="1194"
CFG_PORT_PTP="1195"
CFG_PROTO="udp"
CFG_TAKEY="ta.key"
CFG_SUBNET="255.255.255.0"
CFG_PREFIX_BRIDGED="10.10.217"
CFG_PREFIX_PTP="10.10.5"
CFG_POOL_DHCP="$CFG_PREFIX_BRIDGED.201 $CFG_PREFIX_BRIDGED.220"
CFG_IP_SERVER="$CFG_PREFIX_BRIDGED.1 255.255.255.0"
CFG_IP_SERVER_PTP="$CFG_PREFIX_PTP.1 255.255.255.0"
CFG_NET_SERVER_PTP="$CFG_PREFIX_PTP.0 255.255.255.0"
CFG_IP_DNS1="62.113.211.118"
CFG_IP_DNS2="62.113.211.228"
CFG_REMOTE_DOMAIN_BRIDGED="tortuga.local"
CFG_REMOTE_DOMAIN_PTP="tortuga.gw"
CFG_IP_REMOTE=""
CFG_REMOTE_CNAME="server"
CFG_CIPHER="AES-256-GCM"
DEFAULT_C="TO"
DEFAULT_ST="-"
DEFAULT_L="-"
DEFAULT_O="-"
CURRENT_CN="none"
PACK="0"
OUT="certs"
DEFAULT_PASS="ahk5HJnjIhOHjkidrVg!2"
CURRENT_PASS="$DEFAULT_PASS"

# Flags
INPUT_PARAMS_INVALID="0"

while getopts "s:u:r:a:d:t:R:P:o:y S C p" opt; do
  case $opt in
    s)
      SET_NAME="$OPTARG"
      ;;
    u)
      USR_NAME="$OPTARG"
      ;;
    r)
      LEN_RSA="$OPTARG"
      ;;
    a)
      LEN_AES="$OPTARG"
      ;;
    d)
      DAYS_VALID="$OPTARG"
      ;;
    t)
      TYPE="$OPTARG"
      ;;
    C)
      CFG_CLIENT="1"
      ;;
    S)
      CFG_SERVER="1"
      ;;
    R)
      CFG_IP_REMOTE="$OPTARG"
      ;;
    p)
      PACK="1"
      ;;
    P)
      CURRENT_PASS="$OPTARG"
      ;;
    o)
      OUT="$OPTARG"
      ;;
    y)
      FORCE_YES="1"
      ;;
    \?)
      INPUT_PARAMS_INVALID="1"
      exit 1
      ;;
    :)
      INPUT_PARAMS_INVALID="1"
      exit 1
      ;;
  esac
done

function run_main() {
    execute
    if [ "$?" == "0" ] ; then
        echo "[+] Task finished with SUCCESS!"
    else
        echo "[-] Task finished with ERRORS!"
    fi
    echo "[*]"
}

function execute() {
    RESULT=1
    debug_banner
    debug_vars_input
    check_vars_input
    if [ "$?" == "0" ] ; then
        echo "[*] Starting desired task..."
        echo "[*] -------------------------------------";
        prepare_folders
        if [ -d "$OUT" ] ; then
            if [ "$TYPE" == "ca" ] ; then
                do_action_ca
                RESULT=$?
            fi
            if [ "$TYPE" == "srv" ] ; then
                do_action_srv
                RESULT=$?
            fi
            if [ "$TYPE" == "usr" ] ; then
                do_action_usr_all
                RESULT=$?
            fi
            if [ "$TYPE" == "all" ] ; then
                do_action_all
                RESULT=$?
            fi
        else
            echo "[-] Outputfolder not valid!";
        fi
        
        

        echo "[*] -------------------------------------";
    fi
    return $RESULT
}

function do_action_all() {

    TYPE="ca"
    do_action_ca

    TYPE="srv"
    do_action_srv

    TYPE="usr"
    do_action_usr_all

    do_action_pack_all
}

function do_action_usr_all() {

    IFS=', ' read -a array <<< "$USR_NAME"
    for index in "${!array[@]}"
    do
        do_action_usr ${array[index]}
    done
}


function do_action_ca() {
    NAME_OUT_KEY="$OUT/$SET_NAME/$TYPE/${TYPE}_key_$SET_NAME.pem"
    NAME_OUT_CRT="$OUT/$SET_NAME/$TYPE/${TYPE}_crt_$SET_NAME.pem"

    mkdir $OUT/$SET_NAME/$TYPE &>/dev/null
    rm -rf $NAME_OUT_KEY &>/dev/null
    rm -rf $NAME_OUT_CRT &>/dev/null
    echo -n "[*] Creating  ${TYPE}- key..."
    echo "$CURRENT_PASS" > passinfile
    echo "$CURRENT_PASS" > passoutfile
    openssl genrsa -passout file:passoutfile -aes$LEN_AES -out $NAME_OUT_KEY $LEN_RSA &>/dev/null
    echo "Done!"
    echo -n "[*] Creating  ${TYPE}-cert..."
    if [ -f $NAME_OUT_KEY ] ; then
        CURRENT_CN="${TYPE}_${SET_NAME}"
        openssl req -new -x509 -passin file:passinfile -passout file:passoutfile -days $DAYS_VALID \
            -key $NAME_OUT_KEY -out $NAME_OUT_CRT -set_serial 1 \
            -subj "/C=$DEFAULT_C/ST=$DEFAULT_ST/L=$DEFAULT_L/O=$DEFAULT_O/CN=$CURRENT_CN" \
            &>/dev/null
        #openssl x509 -in $NAME_OUT_CRT -text

        rm -rf passinfile
        rm -rf passoutfile
        if [ -f $NAME_OUT_CRT ] ; then
            echo "$CURRENT_PASS" > $OUT/$SET_NAME/$TYPE/pass.txt
            echo "01" > $OUT/$SET_NAME/$TYPE/serial
            chmod -R 700 $OUT/$SET_NAME/$TYPE/
            sudo openvpn --genkey --secret $OUT/$SET_NAME/$TYPE/$CFG_TAKEY
            if [ -f $OUT/$SET_NAME/$TYPE/$CFG_TAKEY ] ; then
                sudo chown $USER:$USER $OUT/$SET_NAME/$TYPE/$CFG_TAKEY 
                echo "Done!"
                if [ "$PACK" == "1" ] ; then
                    do_action_pack_pki
                fi
            else
                echo "[-] The ta-key was not created!";
            fi
        else
            echo "[-] ${TYPE}-cert not created!";
            return 1
        fi
    else
        echo "[-] ${TYPE}-key not created!";
        return 2
    fi

    return 0
}



function do_action_srv() {
    FROM_KEY="$OUT/$SET_NAME/ca/ca_key_$SET_NAME.pem"
    FROM_CRT="$OUT/$SET_NAME/ca/ca_crt_$SET_NAME.pem"
    FROM_SER="$OUT/$SET_NAME/ca/serial"

    NAME_OUT_KEY="$OUT/$SET_NAME/$TYPE/${TYPE}_key_$SET_NAME.pem"
    NAME_OUT_CRT="$OUT/$SET_NAME/$TYPE/${TYPE}_crt_$SET_NAME.pem"
    NAME_OUT_CSR="$OUT/$SET_NAME/$TYPE/${TYPE}_csr_$SET_NAME.pem"
    NAME_OUT_DH="$OUT/$SET_NAME/$TYPE/dh$LEN_RSA.pem"



    mkdir $OUT/$SET_NAME/$TYPE &>/dev/null
    rm -rf $NAME_OUT_KEY &>/dev/null
    rm -rf $NAME_OUT_CRT &>/dev/null
    echo -n "[*] Creating ${TYPE}- key..."
    CURRENT_CN="${TYPE}_${SET_NAME}"
    openssl req -new -newkey rsa:$LEN_RSA -out $NAME_OUT_CSR -nodes -keyout $NAME_OUT_KEY -days $DAYS_VALID \
        -subj "/C=$DEFAULT_C/ST=$DEFAULT_ST/L=$DEFAULT_L/O=$DEFAULT_O/CN=$CURRENT_CN" &>/dev/null
    echo "Done!"
    echo -n "[*] Creating ${TYPE}-cert..."
    if [ -f $NAME_OUT_KEY ] ; then
        echo "Done!"
        echo "$CURRENT_PASS" > passinfile
        openssl x509 -req -passin file:passinfile -in $NAME_OUT_CSR -out $NAME_OUT_CRT \
            -CA $FROM_CRT -CAkey $FROM_KEY -CAserial $FROM_SER -days $DAYS_VALID \
            -extfile <( printf "keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment, keyAgreement\n" \
                && printf "extendedKeyUsage = critical, serverAuth\n" \
                && printf "subjectAltName=IP:$CFG_IP_REMOTE") \
            &>/dev/null
        #openssl x509 -in $NAME_OUT_CRT -text

        rm -rf passinfile
        if [ -f $NAME_OUT_CRT ] ; then
            rm -rf $NAME_OUT_CSR
            echo -n "[*] Creating dhparam ..."
            openssl dhparam -out $NAME_OUT_DH $LEN_RSA &>/dev/null
            if [ -f $NAME_OUT_DH ]
            then
                chmod -R 700 $OUT/$SET_NAME/

                if [ -f $OUT/$SET_NAME/ca/$CFG_TAKEY ] ; then
                    cp $OUT/$SET_NAME/ca/$CFG_TAKEY $OUT/$SET_NAME/$TYPE/$CFG_TAKEY
                    cp $OUT/$SET_NAME/ca/ca_crt_$SET_NAME.pem $OUT/$SET_NAME/$TYPE/ca_crt_$SET_NAME.pem

                    echo "Done!"
                    if [ "$CFG_SERVER" == "1" ] ; then
                        do_action_config_server_bridged
                        do_action_config_server_ptp
                    fi
                    if [ "$PACK" == "1" ] ; then
                        do_action_pack_server
                    fi
                else
                    echo "[-] The ta-key was not created!";
                fi
            else
                echo "[-] dhparam not created!";
                return 1
            fi
        else
            echo "[-] ${TYPE}-cert not created!";
            return 2
        fi
    else
        echo "[-] ${TYPE}-key not created!";
        return 3
    fi

    return 0
}

function do_action_usr() {
    UNAME="$1"
    FROM_KEY="$OUT/$SET_NAME/ca/ca_key_$SET_NAME.pem"
    FROM_CRT="$OUT/$SET_NAME/ca/ca_crt_$SET_NAME.pem"
    FROM_SER="$OUT/$SET_NAME/ca/serial"

    NAME_OUT_KEY="$OUT/$SET_NAME/$TYPE/${UNAME}/${UNAME}_key_$SET_NAME.pem"
    NAME_OUT_CRT="$OUT/$SET_NAME/$TYPE/${UNAME}/${UNAME}_crt_$SET_NAME.pem"
    NAME_OUT_CSR="$OUT/$SET_NAME/$TYPE/${UNAME}/${UNAME}_csr_$SET_NAME.pem"

    mkdir $OUT/$SET_NAME/$TYPE &>/dev/null
    mkdir $OUT/$SET_NAME/$TYPE/${UNAME} &>/dev/null

    rm -rf $NAME_OUT_KEY &>/dev/null
    rm -rf $NAME_OUT_CRT &>/dev/null
    echo -n "[*] Creating ${TYPE}- key..."
    CURRENT_CN="${UNAME}_${SET_NAME}"
    echo "$CURRENT_PASS" > passoutfile
    openssl req -new -newkey rsa:$LEN_RSA -out "$NAME_OUT_CSR" -nodes -keyout "$NAME_OUT_KEY" -days $DAYS_VALID \
        -subj "/C=$DEFAULT_C/ST=$DEFAULT_ST/L=$DEFAULT_L/O=$DEFAULT_O/CN=$CURRENT_CN" -passout file:passoutfile \
        &>/dev/null
    rm -rf passoutfile
    echo "Done!"
    echo -n "[*] Creating ${TYPE}-cert..."
    if [ -f $NAME_OUT_CSR ] ; then
        echo "$CURRENT_PASS" > passinfile
        openssl x509 -req -passin file:passinfile -in $NAME_OUT_CSR -out $NAME_OUT_CRT \
            -CA $FROM_CRT -CAkey $FROM_KEY -CAserial $FROM_SER -days $DAYS_VALID \
            -extfile <( printf "keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment\n" \
                        && printf "extendedKeyUsage = critical, clientAuth\n" ) \
            &>/dev/null
		#openssl x509 -in $NAME_OUT_CRT -text
        
		rm -rf passinfile
        if [ -f $NAME_OUT_CRT ] ; then
            rm -rf $NAME_OUT_CSR

                if [ -f $OUT/$SET_NAME/ca/$CFG_TAKEY ] ; then
                    cp $OUT/$SET_NAME/ca/$CFG_TAKEY $OUT/$SET_NAME/$TYPE/$UNAME/$CFG_TAKEY
                    cp $OUT/$SET_NAME/ca/ca_crt_$SET_NAME.pem $OUT/$SET_NAME/$TYPE/$UNAME/ca_crt_$SET_NAME.pem
                    echo "Done!"
                    if [ "$CFG_CLIENT" == "1" ] ; then
                        do_action_config_client_bridged $UNAME
                        do_action_config_client_ptp $UNAME
                    fi
                    if [ "$PACK" == "1" ] ; then
                        do_action_pack_client $UNAME
                    fi
                else
                    echo "[-] The ta-key was not created!";
                fi
        else
            echo "[-] ${TYPE}-cert not created!";
            return 1
        fi
    else
        echo "[-] ${TYPE}-key not created!";
        return 2
    fi

    return 0
}

function do_action_config_server_bridged(){
    # Prepare
    UNAME="$1"
    CONF_OUT="$OUT/$SET_NAME/$TYPE/${SET_NAME}_bridged.conf"
    cd $OUT/$SET_NAME/$TYPE/
    mkdir certs &>/dev/null
    mkdir status &>/dev/null
    mkdir ccd &>/dev/null
    mv *.pem certs/ &>/dev/null
    mv *.key certs/ &>/dev/null
    cd - &>/dev/null
    echo -n "[*] Creating srv-conf..."
    # Connection
    echo "# Connection" > $CONF_OUT
    echo "mode server" >> $CONF_OUT
    echo "tls-server" >> $CONF_OUT
    echo "dev tapBridge" >> $CONF_OUT
    echo "dev-type tap" >> $CONF_OUT
    echo "proto ${CFG_PROTO}" >> $CONF_OUT
    echo "port $CFG_PORT_BRIDGE" >> $CONF_OUT
    echo "client-to-client" >> $CONF_OUT
    echo "remote-cert-tls client" >> $CONF_OUT
    echo "local $CFG_IP_REMOTE" >> $CONF_OUT
    echo "" >> $CONF_OUT
    # Certs
    echo "# Certs" >> $CONF_OUT
    echo "dh   certs/dh$LEN_RSA.pem" >> $CONF_OUT
    echo "ca   certs/ca_crt_$SET_NAME.pem" >> $CONF_OUT
    echo "cert certs/srv_crt_$SET_NAME.pem" >> $CONF_OUT
    echo "key  certs/srv_key_$SET_NAME.pem" >> $CONF_OUT
    echo "tls-auth certs/ta.key 0" >> $CONF_OUT
    echo "" >> $CONF_OUT
    # Files
    echo '# Files' >> $CONF_OUT
    echo "chroot /etc/openvpn/server/${SET_NAME}/" >> $CONF_OUT
    echo "status status/openvpn_status.log" >> $CONF_OUT
    echo "ifconfig-pool-persist status/ipp.txt" >> $CONF_OUT
    echo "log-append /var/log/openvpn/${SET_NAME}_bridged.log" >> $CONF_OUT
    echo "" >> $CONF_OUT
    # IP
    echo "# IP" >> $CONF_OUT
    echo "ifconfig $CFG_IP_SERVER" >> $CONF_OUT
    echo "ifconfig-pool $CFG_POOL_DHCP $CFG_SUBNET" >> $CONF_OUT
    echo "" >> $CONF_OUT
    # Routes
    echo "# Routes" >> $CONF_OUT
    echo "push \"route-gateway ${CFG_PREFIX_BRIDGED}.1\"" >> $CONF_OUT
    echo "" >> $CONF_OUT
    # Options
    echo "# Options" >> $CONF_OUT
    echo "user nobody " >> $CONF_OUT
    echo "group nogroup" >> $CONF_OUT
    echo "tun-mtu 1500" >> $CONF_OUT
    echo "mssfix" >> $CONF_OUT
    echo "auth SHA512" >> $CONF_OUT
    echo "cipher $CFG_CIPHER" >> $CONF_OUT
    echo "persist-key" >> $CONF_OUT
    echo "persist-tun" >> $CONF_OUT
    echo "keepalive 10 120" >> $CONF_OUT
    echo "verb 1" >> $CONF_OUT
    echo "Done!"
}

function do_action_config_server_ptp(){
    # Prepare
    UNAME="$1"
    CONF_OUT="$OUT/$SET_NAME/$TYPE/${SET_NAME}_ptp.conf"
    echo -n "[*] Creating srv-conf..."
    # Connection
    echo "# Connection" > $CONF_OUT
    echo "mode server" >> $CONF_OUT
    echo "tls-server" >> $CONF_OUT
    echo "dev tunVpnGW" >> $CONF_OUT
    echo "dev-type tun" >> $CONF_OUT
    echo "proto ${CFG_PROTO}" >> $CONF_OUT
    echo "port $CFG_PORT_PTP" >> $CONF_OUT
    echo "client-to-client" >> $CONF_OUT
    echo "local $CFG_IP_REMOTE" >> $CONF_OUT
    echo "remote-cert-tls client" >> $CONF_OUT
    echo "" >> $CONF_OUT
    # Certs
    echo "# Certs" >> $CONF_OUT
    echo "dh   certs/dh$LEN_RSA.pem" >> $CONF_OUT
    echo "ca   certs/ca_crt_$SET_NAME.pem" >> $CONF_OUT
    echo "cert certs/srv_crt_$SET_NAME.pem" >> $CONF_OUT
    echo "key  certs/srv_key_$SET_NAME.pem" >> $CONF_OUT
    echo "tls-auth certs/ta.key 0" >> $CONF_OUT
    echo "" >> $CONF_OUT
    # Files
    echo '# Files' >> $CONF_OUT
    echo "chroot /etc/openvpn/server/${SET_NAME}/" >> $CONF_OUT
    echo "status status/openvpn_status.log" >> $CONF_OUT
    echo "ifconfig-pool-persist status/ipp.txt" >> $CONF_OUT
    echo "log-append /var/log/openvpn/${SET_NAME}_ptp.log" >> $CONF_OUT
    echo "" >> $CONF_OUT
    # IP
    echo "# IP" >> $CONF_OUT
    echo "server $CFG_NET_SERVER_PTP" >> $CONF_OUT
    echo "" >> $CONF_OUT
    # Routes
    echo "# Routes" >> $CONF_OUT
    echo "push \"route $CFG_NET_SERVER_PTP\"" >> $CONF_OUT
    echo "push \"dhcp-option redirect-gateway def1\"" >> $CONF_OUT
    echo "push \"dhcp-option remote-gateway $CFG_PREFIX_PTP.1\"" >> $CONF_OUT
    echo "push \"dhcp-option DNS $CFG_IP_DNS1\"" >> $CONF_OUT
    echo "push \"dhcp-option DNS $CFG_IP_DNS2\"" >> $CONF_OUT
    echo "push \"dhcp-option DOMAIN $CFG_REMOTE_DOMAIN_PTP\"" >> $CONF_OUT
    echo "push \"dhcp-option SEARCH $CFG_REMOTE_DOMAIN_PTP\"" >> $CONF_OUT
    echo "" >> $CONF_OUT
    # Options
    echo "# Options" >> $CONF_OUT
    echo "user nobody " >> $CONF_OUT
    echo "group nogroup" >> $CONF_OUT
    echo "tun-mtu 1500" >> $CONF_OUT
    echo "mssfix" >> $CONF_OUT
    echo "auth SHA512" >> $CONF_OUT
    echo "cipher $CFG_CIPHER" >> $CONF_OUT
    echo "persist-key" >> $CONF_OUT
    echo "persist-tun" >> $CONF_OUT
    echo "keepalive 10 120" >> $CONF_OUT
    echo "verb 1" >> $CONF_OUT
    echo "Done!"
}

function do_action_config_client_bridged(){
    # Prepare
    UNAME="$1"
    CONF_OUT="$OUT/$SET_NAME/$TYPE/${UNAME}/${SET_NAME}_bridged.conf"
    cd $OUT/$SET_NAME/$TYPE/${UNAME}/
    mkdir certs &>/dev/null
    mkdir status &>/dev/null
    mv *.pem certs/ &>/dev/null
    mv *.key certs/ &>/dev/null
    cd - &>/dev/null
    echo -n "[*] Creating usr-conf..."
    # Connection
    echo "# Connection" > $CONF_OUT
    echo "client" >> $CONF_OUT
    echo "#tls-remote srv_${SET_NAME}" >> $CONF_OUT
    echo "remote $CFG_IP_REMOTE $CFG_PORT_BRIDGE" >> $CONF_OUT
    echo "dev tap" >> $CONF_OUT
    echo "proto $CFG_PROTO" >> $CONF_OUT
    echo "port $CFG_PORT_BRIDGE" >> $CONF_OUT
    echo "remote-cert-tls server" >> $CONF_OUT
    echo "verify-x509-name 'C=TO, ST=-, L=-, O=-, CN=srv_${SET_NAME}'" >> $CONF_OUT
    echo "" >> $CONF_OUT
    # Certs
    echo "# Certs" >> $CONF_OUT
    echo "ca   certs/ca_crt_$SET_NAME.pem" >> $CONF_OUT
    echo "cert certs/${UNAME}_crt_$SET_NAME.pem" >> $CONF_OUT
    echo "key  certs/${UNAME}_key_$SET_NAME.pem" >> $CONF_OUT
    echo "tls-auth certs/ta.key 1" >> $CONF_OUT
    echo "" >> $CONF_OUT
    # Options
    echo "# Options" >> $CONF_OUT
    echo "float " >> $CONF_OUT
    echo "nobind" >> $CONF_OUT
    echo "tun-mtu 1500" >> $CONF_OUT
    echo "mssfix" >> $CONF_OUT
    echo "auth SHA512" >> $CONF_OUT
    echo "cipher $CFG_CIPHER" >> $CONF_OUT
    echo "persist-key" >> $CONF_OUT
    echo "persist-tun" >> $CONF_OUT
    echo "verb 1" >> $CONF_OUT
    cp $CONF_OUT $OUT/$SET_NAME/$TYPE/${UNAME}/${SET_NAME}_bridged.ovpn
    echo "Done!"
}

function do_action_config_client_ptp(){
    # Prepare
    UNAME="$1"
    CONF_OUT="$OUT/$SET_NAME/$TYPE/${UNAME}/${SET_NAME}_ptp.conf"
    echo -n "[*] Creating usr-conf..."
    # Connection
    echo "# Connection" > $CONF_OUT
    echo "client" >> $CONF_OUT
    echo "#tls-remote srv_${SET_NAME}" >> $CONF_OUT
    echo "remote $CFG_IP_REMOTE $CFG_PORT_PTP" >> $CONF_OUT
    echo "dev tun" >> $CONF_OUT
    echo "proto $CFG_PROTO" >> $CONF_OUT
    echo "port $CFG_PORT_PTP" >> $CONF_OUT
    echo "remote-cert-tls server" >> $CONF_OUT
    echo "verify-x509-name 'C=TO, ST=-, L=-, O=-, CN=srv_${SET_NAME}'" >> $CONF_OUT
    echo "" >> $CONF_OUT
    # Certs
    echo "# Certs" >> $CONF_OUT
    echo "ca   certs/ca_crt_$SET_NAME.pem" >> $CONF_OUT
    echo "cert certs/${UNAME}_crt_$SET_NAME.pem" >> $CONF_OUT
    echo "key  certs/${UNAME}_key_$SET_NAME.pem" >> $CONF_OUT
    echo "tls-auth certs/ta.key 1" >> $CONF_OUT
    echo "" >> $CONF_OUT
    # Options
    echo "# Options" >> $CONF_OUT
    echo "redirect-gateway def1" >> $CONF_OUT
    echo "float " >> $CONF_OUT
    echo "nobind" >> $CONF_OUT
    echo "tun-mtu 1500" >> $CONF_OUT
    echo "mssfix" >> $CONF_OUT
    echo "auth SHA512" >> $CONF_OUT
    echo "cipher $CFG_CIPHER" >> $CONF_OUT
    echo "persist-key" >> $CONF_OUT
    echo "persist-tun" >> $CONF_OUT
    echo "verb 1" >> $CONF_OUT
    cp $CONF_OUT $OUT/$SET_NAME/$TYPE/${UNAME}/${SET_NAME}_ptp.ovpn
    echo "Done!"
}

function do_action_pack_all(){
    FOLDER_IN="$OUT/$SET_NAME/"
    FOLDER_OUT="$OUT/$SET_NAME/archives/"
    ARCHIVE_NAME="all_${SET_NAME}.zip"

    mkdir $FOLDER_OUT &>/dev/null
    rm ${FOLDER_OUT}${ARCHIVE_NAME} &>/dev/null

    cd $FOLDER_IN
    zip -r $ARCHIVE_NAME ./ &>/dev/null
    cd - &>/dev/null
    mv ${FOLDER_IN}${ARCHIVE_NAME} $FOLDER_OUT
}

function do_action_pack_pki(){
    FOLDER_IN="$OUT/$SET_NAME/ca/"
    FOLDER_OUT="$OUT/$SET_NAME/archives/"
    ARCHIVE_NAME="pki_${SET_NAME}.zip"

    mkdir $FOLDER_OUT &>/dev/null
    rm ${FOLDER_OUT}${ARCHIVE_NAME} &>/dev/null

    cd $FOLDER_IN
    zip -r $ARCHIVE_NAME ./ &>/dev/null
    cd - &>/dev/null
    mv ${FOLDER_IN}${ARCHIVE_NAME} $FOLDER_OUT
}

function do_action_pack_server(){
    FOLDER_IN="$OUT/$SET_NAME/srv/"
    FOLDER_OUT="$OUT/$SET_NAME/archives/"
    ARCHIVE_NAME="srv_${SET_NAME}.zip"

    mkdir $FOLDER_OUT &>/dev/null

    cp $OUT/$SET_NAME/ca/ca_crt* $OUT/$SET_NAME/srv/certs
    rm ${FOLDER_OUT}${ARCHIVE_NAME} &>/dev/null

    cd $FOLDER_IN
    chmod og-rwx ./ -R
    zip -r $ARCHIVE_NAME ./ &>/dev/null
    cd - &>/dev/null

    mv ${FOLDER_IN}${ARCHIVE_NAME} $FOLDER_OUT
}

function do_action_pack_client(){
    UNAME="$1"
    FOLDER_IN="$OUT/$SET_NAME/usr/${UNAME}/"
    FOLDER_OUT="$OUT/$SET_NAME/archives/"
    ARCHIVE_NAME="usr_${SET_NAME}_${UNAME}.zip"

    mkdir $FOLDER_OUT &>/dev/null

    cp $OUT/$SET_NAME/ca/ca_crt* $OUT/$SET_NAME/usr/${UNAME}/certs
    rm ${FOLDER_OUT}${ARCHIVE_NAME} &>/dev/null

    cd $FOLDER_IN
    chmod og-rwx ./ -R
    zip -r $ARCHIVE_NAME ./ &>/dev/null
    cd - &>/dev/null

    mv ${FOLDER_IN}${ARCHIVE_NAME} $FOLDER_OUT
}

function prepare_folders() {
    mkdir -p $OUT/$SET_NAME &>/dev/null
}

function debug_banner() {
    echo "[*]"
    echo "[*] +~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+"
    echo "[*] | Certificate generator script v$VERSION |"
    echo "[*] +~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+"
    echo "[*]"
}

function debug_vars_input() {
    echo "[*]"
    echo "[*] Current Options:"
    echo "[*] -------------------------------------";
    echo "[*] Server IP         : $CFG_IP_REMOTE";
    echo "[*] Output folder     : '$OUT'";
    echo "[*] Desired action    : '$TYPE'";
    echo "[*] Set Name          : '$SET_NAME'";
    echo "[*] User Name(s)      : '$USR_NAME'";
    echo "[*] Length RSA Keys   : $LEN_RSA";
    echo "[*] Length AES Keys   : $LEN_AES";
    echo "[*] Lifetime in days  : $DAYS_VALID";
    echo "[*] Client config     : $CFG_CLIENT";
    echo "[*] Server config     : $CFG_SERVER";
    echo "[*] Pack archive      : $PACK";
    echo "[*] Force YES         : $FORCE_YES";
    echo "[*] -------------------------------------";
    echo "[*]"
}

function debug_usage() {
    echo "[*]"
    echo "[*] Usage:"
    echo "[*] ---------------------------------"
    echo "[*] /bin/bash> ./$0 -o out -R 123.4.5.6 -r LEN-RSA -a LEN-AES -d DAYS-VALID -s SET-NAME -y -u [ USR-NAME | USR-LIST ] -t [ all | ca | srv | usr ]"
    echo "[*] ---------------------------------"
    echo "[*]"
    echo "[*] Options:"
    echo "[*] ---------------------------------"
    echo "[*] -R : Remote IP"
    echo "[*] -o : Output folder"
    echo "[*] -r : RSA-Size"
    echo "[*] -a : AES-Size"
    echo "[*] -d : Days before expiration"
    echo "[*] -s : Set name"
    echo "[*] -u : User or Userlist"
    echo "[*] -t : Type of certificate to create (ca,srv,usr,all)"
    echo "[*] -C : create client config"
    echo "[*] -S : create server config"
    echo "[*] -p : pack archives"
    echo "[*] -y : Skips confirmation"
    echo "[*] ---------------------------------"
    echo "[*]"
}

function check_vars_input() {

    # Check arguments
    if [ "$USR_NAME" == "" -a "$TYPE" == "usr" ] ; then
        INPUT_PARAMS_INVALID="1"
    fi
    if [ "$USR_NAME" == "" -a "$TYPE" == "all" ] ; then
        INPUT_PARAMS_INVALID="1"
    fi

    if [ "$INPUT_PARAMS_INVALID" == "1" -o "$SET_NAME" == "" -o "$LEN_RSA" == "" -o "$LEN_AES" == "" -o "$DAYS_VALID" == "" -o "$TYPE" == "" ] ; then
        echo "[-]"
        echo "[-] Missing Arguments:"
        if [ "$TYPE" == "" ] ; then
            echo "[-] -t : TYPE-OF-ACTION"
        fi
        if [ "$SET_NAME" == "" ] ; then
            echo "[-] -s : SET-NAME"
        fi
        if [ "$LEN_RSA" == "" ] ; then
            echo "[-] -r  : RSA-LENGTH"
        fi
        if [ "$LEN_AES" == "" ] ; then
            echo "[-] -a : AES-LENGTH"
        fi
        if [ "$DAYS_VALID" == "" ] ; then
            echo "[-] -d : DAYS-VALID"
        fi
        if [ "$USR_NAME" == "" -a "$TYPE" == "usr" ] ; then
            echo "[-] -u : USR-NAME"
        fi
        if [ "$USR_NAME" == "" -a "$TYPE" == "all" ] ; then
            echo "[-] -u : USR-LIST"
        fi

        debug_usage
        echo "[-]"
        echo "[-] Required arguments missing!"
        echo "[-] Exiting now..."
        echo "[-]"
        return 2
    else
        # Check action
        if [ "$TYPE" != "all" -a "$TYPE" != "ca" -a "$TYPE" != "srv" -a "$TYPE" != "usr" ] ; then
            debug_usage
            echo "[-]"
            echo "[-] Desired action not recognized: -a $TYPE"
            echo "[-] Exiting now..."
            echo "[-]"
            return 1
        fi

        # Check confirmation
        if [ "$FORCE_YES" == "0" ] ; then
            echo -n "[?] Press [y|Y] to confirm parameters: "
            read READ_TEST
        else
            READ_TEST="y"
        fi

        # Check password
        if [ "$DEFAULT_PASS" == "$CURRENT_PASS" ] ; then
            PW_FILE="$OUT/$SET_NAME/ca/pass.txt"
            if [ -f $PW_FILE ] ; then
                PW=`cat "$OUT/$SET_NAME/ca/pass.txt"`
                if [ "$PW" != "" ] ; then
                    CURRENT_PASS=$PW
                fi
            fi
        fi

        if [ "$READ_TEST" == "y" -o "$READ_TEST" == "Y" ] ; then
            echo "[+] Input parameters accepted!"
        else
            debug_usage
            echo "[-] Process cancelled by user!"
            echo "[-] Exiting now..."
            echo "[-]"
            return 3
        fi

    fi

    return 0
}

run_main

