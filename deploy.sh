#!/bin/bash
#
#
#           MPS - MISP Professional Services
# -= MPS IDIAM - Instance Deployment, Inventory And Monitoring =-
#
# (C) 2025-04-24 CIRCL - Computer Incident Response Center Luxembourg
# (C) 2025-04-24 Sascha 'rommelfs' Rommelfangen
#
# MPS IDIAM is licensed under the GNU AFFERO GENERAL PUBLIC LICENSE version 3.
#
#
#
#

before=$(set -o posix; set | sort);
source deploy.config
source private.config
source static.config
MISP_API_KEY=""

while true; do
    read -p "Do you wish to review the variables before proceeding? " yn
    case $yn in
        [Yy]* ) comm -13 <(printf %s "$before") <(set -o posix; set | sort | uniq) ; break;;
        [Nn]* ) echo "Ok, let's continue." ; break;;
        * ) echo "Please answer yes or no.";;
    esac
done
while true; do
    read -p "Shall we deploy? " yn
    case $yn in
        [Yy]* ) break;;
        [Nn]* ) echo "Good bye!" ; exit;;
        * ) echo "Please answer yes or no.";;
    esac
done

echo "Deployment started."

prepare_lxc (){
  echo "Creating LXC container."
  lxc launch $CONTAINER_OS $CONTAINER --profile default --profile macvlan
  echo "Configuring LXC."
  lxc config set $CONTAINER security.nesting true
}

prepare_netplan (){
  echo "Setting up the network."
  $EXEC "cat << EOF > ${NETPLAN_FILE}
network:
  ethernets:
    eth0:
      dhcp4: false
      dhcp6: false
      addresses:
        - $IPv4_ADDR
        - $IPv6_ADDR
      nameservers:
        addresses:
          - $IPv4_DNS
          - $IPv6_DNS
      routes:
        - to: default
          via: $IPv4_ROUTE
        - to: "::/0"
          via: $IPv6_ROUTE
  version: 2
EOF"
  $EXEC "/usr/bin/chmod 400 $NETPLAN_FILE"
  $EXEC "/usr/sbin/netplan apply"
  echo "Waiting 10 seconds for the network to become active"
  sleep 10
}

prepare_snmp () {
  echo "Setting up SNMP."
  $EXEC "apt-get -y install lldpd snmpd lm-sensors p7zip-full &&\
         echo DAEMON_ARGS='\"-x -c -s -e\"'  >> /etc/default/lldpd &&\
         /etc/init.d/lldpd restart"
  $EXEC "echo 'createUser ${SNMP_user}  ${SNMP_proto} "${SNMP_key}"' >> /var/lib/snmp/snmpd.conf"
  $EXEC "cat << EOF > /etc/snmp/snmpd.conf
agentAddress  udp:161
dontLogTCPWrappersConnects yes
createUser ${SNMP_user}  ${SNMP_proto} "${SNMP_key}"
view   systemonly  included   .1.3.6.1.2.1.1
view   systemonly  included   .1.3.6.1.2.1.25.1
rouser   ${SNMP_user}
sysLocation    ${SNMP_location}
sysContact     ${SNMP_contact} <${EMAIL_ADDR}>
sysServices    72
disk       /     50000000
disk       /var  5%
includeAllDisks  10%
load   12 10 5
iquerySecName   internalUser
rouser          internalUser
master          agentx
EOF"
  $EXEC "/etc/init.d/snmpd restart"
}

prepare_update () {
  echo "Updating the OS."
  $EXEC "apt -y update"
  $EXEC "apt -y upgrade"
}

prepare_certbot () {
  echo "Installing Letsencrypt (certbot) and requesting certificate."
  $EXEC "apt -y install certbot python3-certbot-apache apache2"
  $EXEC "certbot --apache -d $FQDN -n --agree-tos --email ${EMAIL_ADDR}"
  $EXEC "a2dissite 000-default-le-ssl.conf"
  $EXEC "systemctl reload apache2"
  $EXEC "echo \"@monthly	/usr/bin/certbot renew\" >> /var/spool/cron/crontabs/root"
}

prepare_MISP () {
  echo "Downloading MISP installer."
  $EXEC "apt -y install curl"
  $EXEC "curl -o INSTALL.ubuntu2404.sh ${MISP_Installer}" 
  $EXEC "cat INSTALL.ubuntu2404.sh | sed -e \"s/PATH_TO_SSL_CERT=''/PATH_TO_SSL_CERT='yes'/\" \
         | sed -e \"s/MISP_DOMAIN='misp.local'/MISP_DOMAIN='${FQDN}'/\"  \
         | sed -e \"s;SSLCertificateFile /etc/ssl/private/misp.local.crt;SSLCertificateFile ${X509_CERT};\" \
         | sed -e \"s;SSLCertificateKeyFile /etc/ssl/private/misp.local.key;SSLCertificateKeyFile ${X509_KEY};\" > INSTALL.ubuntu2404-patched.sh"
  echo "Patching MISP installer."
  $EXEC "chmod a+x INSTALL.ubuntu2404-patched.sh"
  echo "Installing MISP."
  $EXEC "./INSTALL.ubuntu2404-patched.sh"
}

prepare_postfix () {
  echo "Installing and configuring postfix."
  $EXEC "apt install -y postfix"
  $EXEC "sudo postconf -e relayhost=[${RELAY_HOST}]"
  $EXEC "echo \"www-data@$FQDN ${MISP_bounce_email}\" >> /etc/postfix/generic"
  $EXEC "postconf -e myhostname=${FQDN}"
  $EXEC "postconf -e smtp_generic_maps=hash:/etc/postfix/generic"
  $EXEC "postmap /etc/postfix/generic"
  $EXEC "/etc/init.d/postfix restart"
}

show_summary () {
  $EXEC "cat /var/log/misp_settings.txt"
  MISP_API_KEY=$($EXEC "cat /var/log/misp_settings.txt"|grep "Admin API key:" | cut -d ":" -f 2|cut -d " " -f 2)
}

prepare_OpenNMS () {
  echo "Setting up the new host in OpenNMS monitoring."
  source opennms-service.config
  # add services in OpenNMS Requisition
  curl -s -i -u ${OpenNMS_user}:${OpenNMS_pass} -H "Content-type: application/xml" -d "<node node-label=\"${FQDN}\" foreign-id=\"${FQDN}\" building=\"Datacenter Luxembourg\"><interface snmp-primary=\"N\" status=\"1\" ip-addr=\"${IPADDR}\" descr=\"\"><monitored-service service-name=\"HTTP\"/><monitored-service service-name=\"HTTPS\"/><monitored-service service-name=\"ICMP\"/><monitored-service service-name=\"MISP-REST-latency:${FQDN}\"/><monitored-service service-name=\"MISP-REST:${FQDN}\"/><monitored-service service-name=\"MISP-Version:${FQDN}\"/><monitored-service service-name=\"MISP-diag:${FQDN}\"/><monitored-service service-name=\"MISP-worker:${FQDN}\"/><monitored-service service-name=\"Process-mariadbd\"/><monitored-service service-name=\"Process-apache2\"/><monitored-service service-name=\"Process-redis-server-6379\"/><monitored-service service-name=\"SNMP\"/><monitored-service service-name=\"SSH\"/><monitored-service service-name=\"Web:${FQDN}\"/><monitored-service service-name=\"X509:${FQDN}\"/></interface><meta-data context=\"requisition\" key=\"misp-apikey\" value=\"${MISP_API_KEY}\"/><meta-data context=\"requisition\" key=\"path\" value=\"/users/login\"/></node>" $OpenNMS_host${OpenNMS_base}/requisitions/${OpenNMS_requisition}/nodes
  # Sync Requisition
  curl -s -i -u ${OpenNMS_user}:${OpenNMS_pass} -X PUT ${OpenNMS_host}${OpenNMS_base}/requisitions/${OpenNMS_requisition}/import?rescanExisting=false
}

prepare_Netbox () {
  echo "Setting up the new host in Netbox inventory."
  H1='accept: application/json'
  H2='Authorization: Token '$Netbox_API_Token''
  H3='Content-Type: application/json'

  RESULT=$(curl -s -X 'POST' \
    ${Netbox_host}${Netbox_API}//virtualization/virtual-machines/ \
    -H "$H1" -H "$H2" -H "$H3" -d '{
    "name": "'$FQDN'",
    "status": "active",
    "site": '${Netbox_site}',
    "cluster": '${Netbox_cluster}',
    "device": '${Netbox_device}',
    "role": '${Netbox_role}'
  }')
  RESULT_ID=$(echo $RESULT | jq ".id")
  if [[ -z "${RESULT_ID//[0-9]}" ]]
  then
    VM_ID=$(echo $RESULT | jq ".id")
  else
    echo $RESULT
    exit 1
  fi

  RESULT=$(curl -s -X 'POST' \
    ${Netbox_host}${Netbox_API}/virtualization/interfaces/ \
    -H "$H1" -H "$H2" -H "$H3" -d '{
    "virtual_machine": {
      "id": '${VM_ID}'
    },
    "name": "eth0",
    "enabled": true
  }')
  RESULT_ID=$(echo $RESULT | jq ".id")
  if [[ -z "${RESULT_ID//[0-9]}" ]]
  then
    IF_ID=$(echo $RESULT | jq ".id")
  else
    echo $RESULT
    exit 1
  fi

  RESULT=$(curl -s -X 'POST' \
    ${Netbox_host}${Netbox_API}/ipam/ip-addresses/ \
    -H "$H1" -H "$H2" -H "$H3" -d '{
    "address": "'$IPv4_ADDR'",
    "status": "active",
    "assigned_object_type": "virtualization.vminterface",
    "assigned_object_id": '$IF_ID',
    "dns_name": "'$FQDN'"
  }')
  RESULT_ID=$(echo $RESULT | jq ".id")
  if [[ -z "${RESULT_ID//[0-9]}" ]]
  then
    IPv4_ID=$(echo $RESULT | jq ".id")
  else
    echo $IPv4_ID
    exit 1
  fi

  RESULT=$(curl -s -X 'POST' \
    ${Netbox_host}${Netbox_API}/ipam/ip-addresses/ \
    -H "$H1" -H "$H2" -H "$H3" -d '{
    "address": "'$IPv6_ADDR'",
    "status": "active",
    "assigned_object_type": "virtualization.vminterface",
    "assigned_object_id": '$IF_ID',
    "dns_name": "'$FQDN'"
  }')
  RESULT_ID=$(echo $RESULT | jq ".id")
  if [[ -z "${RESULT_ID//[0-9]}" ]]
  then
    IPv6_ID=$(echo $RESULT | jq ".id")
  else
    echo $IPv6_ID
    exit 1
  fi

  RESULT=$(curl -s -X 'PATCH' \
    ${Netbox_host}${Netbox_API}/virtualization/virtual-machines/$VM_ID/ \
    -H "$H1" -H "$H2" -H "$H3" -d '{
    "primary_ip4": {
    "address": "'$IPv4_ADDR'"
    },
    "primary_ip6": {
      "address": "'$IPv6_ADDR'"
    },
    "custom_fields": {
      "monitored": true
    }
  }')
  RESULT_ID=$(echo $RESULT | jq ".id")
  if [[ -z "${RESULT_ID//[0-9]}" ]]
  then
    RESULT=$(echo $RESULT | jq ".id")
  else
    echo RESULT
    exit 1
  fi
  echo "Netbox Virtual Machine $FQDN successfully created with id $VM_ID."
}

ingest_MISP_data () {
  echo "Ingest MISP data."
  $EXEC "cat << EOF > misp-ingest.sh
#!/bin/bash
curl -X POST https://${FQDN}/events \
  -H \"Authorization: ${MISP_API_KEY}\" \
  -H \"Accept: application/json\" \
  -H \"Content-Type: application/json\" \
  -d '{
        \"Event\": {
          \"info\": \"Automated event for monitoring\",
          \"distribution\": \"0\",
          \"Attribute\": [
            {
              \"type\": \"ip-src\",
              \"category\": \"Network activity\",
              \"value\": \"8.8.8.8\",
              \"to_ids\": true,
              \"distribution\": \"0\"
            }
          ]
        }
      }'
EOF"
  $EXEC "chmod a+x misp-ingest.sh"
  $EXEC "./misp-ingest.sh"
}

IPADDR=$(echo $IPv4_ADDR | cut -d "/" -f 1) 

#prepare_lxc
#prepare_netplan
#prepare_update
#prepare_snmp
#prepare_certbot
#prepare_MISP
#prepare_postfix
show_summary
prepare_OpenNMS
#prepare_Netbox
#ingest_MISP_data

exit 0
