#!/bin/bash
#
# Copyright 2019,2020 Hewlett Packard Enterprise Development LP
#
#set -x
#set -e

source $BUNDLE_COMMON_DIR/common.sh
source ${BUNDLE_COMMON_DIR}/storage-common.sh
source ${BUNDLE_COMMON_DIR}/airgap-common.sh

KUBEADM_SWAP_OPTION="--ignore-preflight-errors Swap,IsDockerSystemdCheck"
SITE_PACKAGES=$(python -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")
OvsUtil="$SITE_PACKAGES/bluedata/ovs/bds-ovs-config.py"
K8S_DIR="$(dirname $(readlink -nf ${BASH_SOURCE[0]}))"
PSP_TEMPLATES_DIR="$K8S_DIR/psp-templates"

MAPR_COMMON_SH="$BUNDLE_COMMON_DIR/mapr-common.sh"
source ${MAPR_COMMON_SH}
MAPR_TEMPLATES_DIR="$K8S_DIR/csimapr-templates"

#If this file changes in bd_mgmt then it must be changed here too!
DOCKER_REPO_PASSWORD_FILE="/opt/bluedata/tmp/airgap-container-repo-password.txt"

# Set K8S RPM package name
K8S_KUBEADM="kubeadm"
K8S_KUBELET="kubelet"
K8S_KUBECTL="kubectl"
K8S_COMMON=
if [[ "${OS_FAMILY}" == "suse" ]]
then
    K8S_KUBEADM="kubernetes-${K8S_KUBEADM}"
    K8S_KUBELET="kubernetes-${K8S_KUBELET}"
    K8S_KUBECTL="kubernetes-client"
    K8S_COMMON="kubernetes-common"
    # Note - this setting is deliberately bogus. Must call build_package_names.
    K8S_CAASP_VERSION="v4.0"
fi

#
# INTERNAL FUNCTIONS
#
build_package_names() {
    if [[ "${OS_FAMILY}" == "suse" ]]
    then
        # Starting with 1.18.x, the packages have versions in the naming.
        case "$1" in
            1.18.*)
                K8S_KUBEADM="kubernetes-1.18-kubeadm"
                K8S_KUBELET="kubernetes-1.18-kubelet"
                K8S_KUBECTL="kubernetes-1.18-client"
                K8S_COMMON=
                K8S_CAASP_VERSION="v4.5"
                ;;
            *)
                K8S_KUBEADM="kubernetes-kubeadm"
                K8S_KUBELET="kubernetes-kubelet"
                K8S_KUBECTL="kubernetes-client"
                K8S_COMMON="kubernetes-common"
                K8S_CAASP_VERSION="v4"
                ;;
        esac
    fi
}

get_rpms() {
    K8S_RPMS=""
    if [[ "${OS_FAMILY}" == "centos" ]]
    then
        if [ "$bds_k8s_version" == "latest" ]
        then
            K8S_RPMS="${K8S_KUBELET} ${K8S_KUBEADM} ${K8S_KUBECTL} kubernetes-cni"
        else
            K8S_RPMS="${K8S_KUBELET}-${bds_k8s_version} ${K8S_KUBEADM}-${bds_k8s_version} ${K8S_KUBECTL}-${bds_k8s_version}"
            # Check if we can get the cni dependency. New patch version of 1.17, 1.16 and 1.18 has
            # deprecated kubernetes-cni, we have to handle the case that this can be an empty string
            CNI_VERSION=$(log_sudo_exec repoquery --requires ${K8S_KUBELET}-${bds_k8s_version} | grep kubernetes-cni)
            if [ -n "$CNI_VERSION" ]
            then
                K8S_RPMS="$K8S_RPMS \"$CNI_VERSION\""
            fi
        fi
    else
        # SUSE
        if [ "$bds_k8s_version" == "latest" ]
        then
            K8S_RPMS="${K8S_KUBEADM} kubernetes-common ${K8S_KUBELET} ${K8S_KUBECTL}"
        else
            build_package_names ${bds_k8s_version}
            K8S_RPMS="${K8S_KUBEADM}-${bds_k8s_version}"
            if [[ -n "$K8S_COMMON" ]]; then
                K8S_RPMS+=" ${K8S_COMMON}-${bds_k8s_version}"
            fi
            K8S_RPMS+=" ${K8S_KUBELET}-${bds_k8s_version} ${K8S_KUBECTL}-${bds_k8s_version}"
        fi
    fi

    echo $K8S_RPMS
}

# For version 1.14.Z return 0
is_experimental() {
    MAJOR_VER=$(echo $bds_k8s_version | cut -d"." -f1)
    MINOR_VER=$(echo $bds_k8s_version | cut -d"." -f2)

    if [ $MAJOR_VER -eq 1 ] && [ $MINOR_VER -eq 14 ];
    then
        return 0
    else
        return 1
    fi
}

# For versions less than 1.17, we have to use beta1
get_kubeadm_api_version() {
    MAJOR_VER=$(echo $bds_k8s_version | cut -d"." -f1)
    MINOR_VER=$(echo $bds_k8s_version | cut -d"." -f2)

    if [ $MAJOR_VER -eq 1 ] && [ $MINOR_VER -lt 17 ];
    then
        echo "kubeadm.k8s.io/v1beta1"
    else
        echo "kubeadm.k8s.io/v1beta2"
    fi
}

# FIXME: we may use skube instead
# For internal function to get etcd version in SLES
get_etcd_version_for_sles() {
    # k8s v1.15.2 - v1.16.2- etcd 3.3.11
    # k8s v1.17.4 - etcd 3.4.3
    # k8s v1.18.6 - etcd 3.4.3 (still)
    local K8S_VERSION=$1
    local SLES_ETCD_VERSION="3.4.3"
    [[ "${K8S_VERSION}" == "1.15"* || "${K8S_VERSION}" == "1.16"* ]] &&  \
        SLES_ETCD_VERSION="3.3.11"
    echo ${SLES_ETCD_VERSION}
}

get_csi_deploy_provisioner_template_prefix() {
    # k8s v1.16 or below - 11_csi-deploy-provisioner-template.yaml
    # k8s v1.17 or above - 12_csi-deploy-provisioner-template.yaml
    local CSI_DEPLOY_PROVISIONER_TEMPLATE_PREFIX="12"
    [[ "$bds_k8s_version" == *"1.15."* || "$bds_k8s_version" == *"1.16."* ]] && \
        CSI_DEPLOY_PROVISIONER_TEMPLATE_PREFIX="11"
    echo ${CSI_DEPLOY_PROVISIONER_TEMPLATE_PREFIX}
}

get_certs_option() {
    if [ "$bds_k8s_version" == "latest" ]
    then
        echo "--upload-certs"
    else
        if is_experimental;
        then
            echo "--experimental-upload-certs"
        else
            echo "--upload-certs"
        fi
    fi
}

get_control_plane_option() {
    if [ "$bds_k8s_version" == "latest" ]
    then
        echo "--control-plane"
    else
        if is_experimental;
        then
            echo "--experimental-control-plane"
        else
            echo "--control-plane"
        fi
    fi
}

delete_fsmounts() {
    local fsmount_host_path=${EPIC_WEBHDFS_SHARE_DIR:-"/opt/bluedata/share/"}

    # unmount all of the FsMounts
    awk '$2 ~ "^'"${fsmount_host_path}"'" { print $2 }' /proc/mounts | sort -r | while read fsMount; do
        util_sudo_umount "${fsMount}"
        util_sudo_rmdir --ignore-fail-on-non-empty "${fsMount}"
    done

    # Delete the top level FsMount mountpoint directories that might
    # be leftover; e.g. the tenant namespace directories. Use rmdir
    # so that we don't delete any data. This assumes the FsMount
    # mountpoints are only 2 directories deep below the hostPath.
    ls "${fsmount_host_path}" | while read mountDir; do
        util_sudo_rmdir --ignore-fail-on-non-empty "${fsmount_host_path}/${mountDir}"
    done
}

#
# API FUNCTIONS BASED ON MODE AND STEP
#
install_stop_kube() {
    return 0
}

install_configure_kube() {
    log_sudo_exec modprobe br_netfilter

    cat <<EOF > /tmp/k8s.conf
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.ipv4.conf.all.rp_filter = 0
EOF

    util_sudo_move_file /tmp/k8s.conf /etc/sysctl.d/k8s.conf

    util_sudo_restorecon "/etc/sysctl.d/k8s.conf"

    log_sudo_exec sysctl --system
    return 0
}

make_k8s_repo_file() {
    # $1 is the location of the tmp file
    # $2 is the baseurl
    # $3 is the gpgkey
    # $4 is the rpmkey

    gpgkeycheck=0
    rpmkeycheck=0
    gpgkey="#gpgkey="
    if [ -n "$3" ]  && [ -n "$4" ]
    then
        gpgkeycheck=1
        rpmkeycheck=1
        gpgkey="gpgkey=$3 $4"
    elif [ -n "$3" ]
    then
       gpgkeycheck=1
       gpgkey="gpgkey=$3"
    elif [ -n "$4" ]
    then
       rpmkeycheck=1
       gpgkey="gpgkey=$4"
    fi

    # use > to wipe the file if it already exists.
    cat << EOF > $1
[kubernetes]
name=Kubernetes
baseurl=$2
enabled=1
gpgcheck=$gpgkeycheck
repo_gpgcheck=$rpmkeycheck
$gpgkey
EOF
}

install_configure_k8s_yum_repo() {
    # for k8s host, we have to setup kubernetes repo as well

    local BDS_K8S_REPO="$OPSYS_YUM_REPO_BASE/bd-kubernetes.repo"
    local BDS_K8S_REPO_TMP="/tmp/$(basename $BDS_K8S_REPO)"

    # If not airgap then make the k8s repo otherwise use the one the customer created in /etc/yum.repos.d/bd-kubernetes.repo
    if [ -z "$bds_k8s_containerrepo" ]
    then
       baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-x86_64
       gpgkey=https://packages.cloud.google.com/yum/doc/yum-key.gpg
       rpmkey=https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg
       # remove any previous airgap version of repo file
       log_sudo_exec "rm -f $BDS_K8S_REPO"
    else
       baseurl=$bds_k8s_repobaseurl
       gpgkey=$bds_k8s_repogpgkey
       rpmkey=$bds_k8s_reporpmgpgkey
    fi

    # baseurl can be undefined in SUSE airgap settings
    if [ -n "$baseurl" ]
    then
        make_k8s_repo_file $BDS_K8S_REPO_TMP $baseurl $gpgkey $rpmkey
        util_sudo_move_file $BDS_K8S_REPO_TMP $BDS_K8S_REPO

        if [[ "${OS_FAMILY}" == 'centos' ]]; then
            # This is here to ensure the gpg keys are in the cache before repoquery runs.
            # Seems like a bug in RHEL7 repoquery not able to retrieve the gpg keys
            log_sudo_exec yum repolist enabled -y
        else
            # Import kubenetes gpg key by refresh command
            log_sudo_exec zypper --gpg-auto-import-keys refresh kubernetes
        fi
    fi
}

setup_docker_creds_for_airgap() {
     registry_type=$1
     registry=$2
     registry_uname=$3
     where=$4

     if [ -n "$registry" ] && [ -n "$registry_uname" ] && [ -n "$where" ];
     then
         log_sudo_exec /opt/bluedata/common-install/scripts/airgap-utils.py --dockercreds    \
                                                                        -t $registry_type    \
                                                                        -r $registry         \
                                                                        -u $registry_uname   \
                                                                        -p $DOCKER_REPO_PASSWORD_FILE  \
                                                                        -d $where
     fi
}

setup_docker_creds() {
    where=$1

    # if the platform and caas registries are the same just add the creds once
    if [ -n "$bds_k8s_containerrepo" ] && [ -n "$bds_k8s_containerrepousername" ]; then
        setup_docker_creds_for_airgap "platform" $bds_k8s_containerrepo $bds_k8s_containerrepousername $where
    fi

    if [[ ("$bds_k8s_containerrepo" != "$bds_k8s_caascontainerrepo") &&  \
          ( -n "$bds_k8s_caascontainerrepo"  &&  -n "$bds_k8s_caascontainerrepousername") ]]; then
           setup_docker_creds_for_airgap "caas" $bds_k8s_caascontainerrepo $bds_k8s_caascontainerrepousername $where
    fi
}

# called once at the beginning of k8s config and once during upgrade
setup_root_docker_creds() {
    if [[ (-n "$bds_k8s_containerrepo"  &&  -n "$bds_k8s_containerrepousername" ) ||   \
          ( -n "$bds_k8s_caascontainerrepo"  &&  -n "$bds_k8s_caascontainerrepousername")  ]];
    then
        # docker credentials file needs to be in /root/.docker before kubeadm  runs
        local root_docker_dir="/root/.docker/"
        log_sudo_exec mkdir -p $root_docker_dir
        setup_docker_creds $root_docker_dir
    fi
}

# called during k8s install (multiple times once for each phase) and during upgrade
setup_kubelet_docker_creds() {
    if [[ (-n "$bds_k8s_containerrepo"  &&  -n "$bds_k8s_containerrepousername" ) || \
          ( -n "$bds_k8s_caascontainerrepo"  &&  -n "$bds_k8s_caascontainerrepousername")  ]];
    then
        # Save existing creds file if any
        if [[ $(log_sudo_exec_no_exit test -f /var/lib/kubelet/config.json >/dev/null) ]]; then
            util_sudo_move_file  /var/lib/kubelet/config.json  /opt/bluedata/tmp
        fi

        local kubelet_dir="/var/lib/kubelet/"

        # Creates /var/lib/kubelet/config.json
        setup_docker_creds $kubelet_dir
    fi
}

restore_docker_creds_for_airgap() {
   if [[ $(log_sudo_exec_no_exit test -f /opt/bluedata/tmp/config.json >/dev/null) ]]; then
        util_sudo_move_file  /opt/bluedata/tmp/config.json /var/lib/kubelet
    fi
}

install_update_cert_permissions() {
    # Since the metrics server needs the root ca cert to have 444 permissions,
    # if we have a cert at /etc/kubernetes/pki/ca.crt, chmod it
    if [[ $(log_sudo_exec_no_exit test -f /etc/kubernetes/pki/ca.crt >/dev/null) ]]; then
        log_sudo_exec chmod 444 /etc/kubernetes/pki/ca.crt
    fi
}

alloc_cpu_power(){
  local ratio=$1
  local num_of_cores=$(awk -F: '/^physical/ && !ID[$2] { P++; ID[$2]=1 }; /^cpu cores/ { CORES=$2 };  END { print CORES*P }' /proc/cpuinfo)
  local cpu_power=$((num_of_cores * 1000))
  local assign_cpu_power=$(echo "${cpu_power} * ${ratio}" | bc | cut -d"." -f1)
  echo ${assign_cpu_power}
}

alloc_mem(){
  local ratio=$1
  local assign_mem=$(free -k | awk -v "ratio=${ratio}" '/Mem:/ {printf("%d",$2 * ratio / 1024 )}')
  echo ${assign_mem}
}

setup_hpecp_plugin() {
    # Download kubectl hpecp plugin from controller and set "x" perms
    log_sudo_exec "curl --noproxy $CONTROLLER -o /usr/bin/kubectl-hpecp -L http://$CONTROLLER/thirdparty/$KUBECTL_HPECP_BIN_PLUGIN"
    log_sudo_exec "chmod 755 /usr/bin/kubectl-hpecp"
}

set_kubelet_flags() {
    local kubeadm_env=/var/lib/kubelet/kubeadm-flags.env

    log_sudo_exec "sed -i 's/\"$/ --feature-gates=RotateKubeletServerCertificate=true --streaming-connection-idle-timeout=5m\"/' $kubeadm_env"
}

extra_kubelet_config() {
    local kubelet_config=/var/lib/kubelet/config.yaml

    log_sudo_append_line ${kubelet_config} "readOnlyPort: 0"
    log_sudo_append_line ${kubelet_config} "protectKernelDefaults: true"
    log_sudo_append_line ${kubelet_config} "TLSCipherSuites: \"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256\""
}

kubernetes_manifest_file_perms() {
    log_sudo_exec "chmod 644 /etc/kubernetes/manifests/etcd.yaml"
}

set_system_reserved(){
    local ratio=$1
    local kubelet_config=/var/lib/kubelet/config.yaml
    if [ "${bds_global_provisionmapr}" = 'true' ] && [ -n "${bds_storage_maprdisks}" ]
    then
        ratio=$(echo ${ratio} | awk '{print $1+0.1}')
    fi
    local systemCPU=$(alloc_cpu_power ${ratio})
    local systemMem=$(alloc_mem ${ratio})
    log_sudo_append_line ${kubelet_config} "systemReserved:"
    log_sudo_append_line ${kubelet_config} "  cpu: ${systemCPU}m"
    log_sudo_append_line ${kubelet_config} "  memory: ${systemMem}Mi"
    log_sudo_exec "grep -e systemReserved ${kubelet_config}"
    restart_kubelet
}

install_config_selinux() {

    file_dir_name=$1
    privilege_t=$2

    if [ "$bds_prechecks_selinux" == "true" ]; then
        log_sudo_exec mkdir -p $file_dir_name
        # Directory and all resources below it get tagged.
        util_sudo_chcon -Rt $privilege_t $file_dir_name
    fi
}

setup_kubeconfig() {
    log_exec mkdir -p ~/.kube
    util_sudo_copy_file /etc/kubernetes/admin.conf ~/.kube/config
    log_sudo_exec chown ${bds_global_user}:${bds_global_group} ~/.kube/config
}

bootstrap_setup_network() {
    # Wait for api server to be up
    Retries=600
    while [ "$Retries" -gt 0 ]; do
        # Fetch number of nodes and validate against the expected one
        NUM_NODES=$(log_exec_no_error "kubectl get node --no-headers | wc -l")
        if [ "$NUM_NODES" -eq "1" ]
        then
            break
        fi
        sleep 10
        Retries=`expr $Retries - 10`
        if [ $Retries -le 0 ]; then
            log "Failed waiting for number of nodes:$NUM_NODES to be 1"
            exit 1
        fi
    done

    log_exec kubectl create -f "$PSP_TEMPLATES_DIR/"

    # Create a tar file with cni-templates folder on the controller
    Uuid=`uuidgen`
    TmpFile="/opt/bluedata/tmp/k8s-${Uuid:0:8}.tar"
    util_remote_exec $bds_global_user $CONTROLLER "tar --dereference --selinux --recursion -cf  $TmpFile -C ${BUNDLE_COMPONENTS_DIR}/k8s cni-templates"
    util_remote_copy_from $CONTROLLER $TmpFile $bds_network_primaryip $TmpFile
    util_remote_exec $bds_global_user $CONTROLLER "rm -f $TmpFile"

    log_exec tar xf $TmpFile -C ${BUNDLE_COMPONENTS_DIR}/k8s cni-templates

    log_exec "${BUNDLE_COMPONENTS_DIR}/k8s/cni-templates/${bds_k8s_cni}-setup.sh"

    rm -f $TmpFile
}

bootstrap_setup_additional_mapr_csi_crd() {
    [[ "$bds_k8s_version" == *"1.15."* || "$bds_k8s_version" == *"1.16."* ]] && return 0
    # copy csi snapshot CRDs to deployment directory
    util_copy_file "$MAPR_TEMPLATES_DIR/13_csi-snapshot-crd.yaml" "$MAPR_TEMPLATES_DIR/csi/13_csi-snapshot-crd.yaml"
}

bootstrap_setup_ext_mapr_csi() {
    util_copy_file "$MAPR_TEMPLATES_DIR/10_csi-deploy-nodeplugin-template.yaml" "$MAPR_TEMPLATES_DIR/csi/10_csi-deploy-nodeplugin.yaml"
    insert_airgap_repo "$MAPR_TEMPLATES_DIR/csi/10_csi-deploy-nodeplugin.yaml"

    # Delete the csi-deploy-provisioner.yaml/snapshot-crd.yaml used in previous setup
    util_delete_file_no_error "$MAPR_TEMPLATES_DIR/csi/11_csi-deploy-provisioner.yaml"
    util_delete_file_no_error "$MAPR_TEMPLATES_DIR/csi/12_csi-deploy-provisioner.yaml"
    util_delete_file_no_error "$MAPR_TEMPLATES_DIR/csi/13_csi-snapshot-crd.yaml"

    util_copy_file "$MAPR_TEMPLATES_DIR/$(get_csi_deploy_provisioner_template_prefix)_csi-deploy-provisioner-template.yaml" \
                   "$MAPR_TEMPLATES_DIR/csi/$(get_csi_deploy_provisioner_template_prefix)_csi-deploy-provisioner.yaml"
    insert_airgap_repo "$MAPR_TEMPLATES_DIR/csi/$(get_csi_deploy_provisioner_template_prefix)_csi-deploy-provisioner.yaml"

    bootstrap_setup_additional_mapr_csi_crd

    source $HOST_MAPR_CONF_DIR/$EXT_HCP_ADMIN_USER
    source $HOST_MAPR_CONF_DIR/$EXT_HCP_ADMIN_PASS
    source $HOST_MAPR_CONF_DIR/$EXT_REST_URL
    source $HOST_MAPR_CONF_DIR/$EXT_MAPR_MOUNT_DIR_COPY
    source $HOST_MAPR_CONF_DIR/$CLDB_NODES_PORTS_LIST_FILE
    source $HOST_MAPR_CONF_DIR/$EXT_SECURE_FILE

    # Construct the secrets (yaml) file, using the saved information
    CSI_USER=$(echo -n "$HCP_ADMIN_USER" | base64 -w 0)
    CSI_PASS=$(echo -n "$HCP_ADMIN_PASS" | base64 -w 0)
    SERVICE_TICKET=$(cat $HOST_MAPR_CONF_DIR/$MAPR_HCP_SERVICE_TICKET | base64 -w 0)

    # To be compliant with DNS-1123, replace . with -
    local SC_NAME=${bds_storage_maprclustername//./-}

    util_copy_file $MAPR_TEMPLATES_DIR/secrets-template.yaml $MAPR_TEMPLATES_DIR/secrets.yaml
    log_exec "sed -i 's|@@@@CSI_USER@@@@|$CSI_USER|g' $MAPR_TEMPLATES_DIR/secrets.yaml"
    log_exec "sed -i 's|@@@@CSI_PASS@@@@|$CSI_PASS|g' $MAPR_TEMPLATES_DIR/secrets.yaml"
    log_exec "sed -i 's|@@@@EPIC_SERVICE_TICKET@@@@|$SERVICE_TICKET|g' $MAPR_TEMPLATES_DIR/secrets.yaml"
    log_exec "sed -i 's|@@@@SECRET_NAME_SUFFIX@@@@|$SC_NAME|g' $MAPR_TEMPLATES_DIR/secrets.yaml"

    # convert comma-separators to spaces
    CLDB_NODES=`echo "$CLDB_NODES_PORTS_LIST" | sed "s/,/ /g"`
    # Construct the StorageClass YAML, using the template for an _external_ MapR cluster, and various
    # saved information on the external MapR cluster
    util_copy_file $MAPR_TEMPLATES_DIR/storageclass-template.yaml $MAPR_TEMPLATES_DIR/storageclass.yaml
    log_exec "sed -i 's|@@@@SC_NAME@@@@|$SC_NAME|g' $MAPR_TEMPLATES_DIR/storageclass.yaml"
    log_exec "sed -i 's|@@@@DEFAULT_SC_FLAG@@@@|true|g' $MAPR_TEMPLATES_DIR/storageclass.yaml"
    log_exec "sed -i 's|@@@@MAPR_REST_SERVERS@@@@|$REST_URL|g' $MAPR_TEMPLATES_DIR/storageclass.yaml"
    log_exec "sed -i 's|@@@@MAPR_CLDB_SERVERS@@@@|$CLDB_NODES|g' $MAPR_TEMPLATES_DIR/storageclass.yaml"
    log_exec "sed -i 's|@@@@MAPR_CLUSTER_NAME@@@@|$bds_storage_maprclustername|g' $MAPR_TEMPLATES_DIR/storageclass.yaml"
    if [ "$SECURE" == "true" ]
    then
        log_exec "sed -i 's|@@@@MAPR_SECURE@@@@|secure|g' $MAPR_TEMPLATES_DIR/storageclass.yaml"
    else
        log_exec "sed -i 's|securityType:|#securityType:|g' $MAPR_TEMPLATES_DIR/storageclass.yaml"
    fi
    log_exec "sed -i 's|@@@@K8S_CLUSTER_NAME@@@@|$bds_k8s_clustername|g' $MAPR_TEMPLATES_DIR/storageclass.yaml"
    # remove the leading slash
    local MAPR_MOUNT_PREFIX=${EXT_MAPR_MOUNT_DIR:1}
    log_exec "sed -i 's|@@@@MAPR_MOUNT_PREFIX@@@@|$MAPR_MOUNT_PREFIX|g' $MAPR_TEMPLATES_DIR/storageclass.yaml"

    if [ "$bds_storage_posixclienttype" == "platinum" ]
    then
        log_exec "sed -i 's|@@@@POSIX_CLIENT_TYPE@@@@|true|g' $MAPR_TEMPLATES_DIR/storageclass.yaml"
    else
        log_exec "sed -i 's|@@@@POSIX_CLIENT_TYPE@@@@|false|g' $MAPR_TEMPLATES_DIR/storageclass.yaml"
    fi
    log_exec "sed -i 's|@@@@SECRET_NAME_SUFFIX@@@@|$SC_NAME|g' $MAPR_TEMPLATES_DIR/storageclass.yaml"

    # apply the YAML files constructed above or saved as copies of user-supplied files
    log_exec kubectl -n hpe-csi create -f $MAPR_TEMPLATES_DIR/csi/
    log_exec kubectl -n hpe-csi create -f $MAPR_TEMPLATES_DIR/secrets.yaml
    log_exec kubectl create -f $MAPR_TEMPLATES_DIR/storageclass.yaml

    log_exec kubectl create namespace $MAPR_EXTERNAL_INFO_NS

    if [ -f "$HOST_MAPR_CONF_DIR/$MAPR_EXTERNAL_SECRETS" ]
    then
        # apply a saved copy of external secrets pre-generated for the external MapR cluster
        log_exec kubectl -n $MAPR_EXTERNAL_INFO_NS create -f $HOST_MAPR_CONF_DIR/$MAPR_EXTERNAL_SECRETS
    fi
}


bootstrap_setup_mapr_csi() {
    [ "${bds_global_provisionmapr}" != "true" ] && return 0

    # For a datafabric cluster, don't configure csi or storageclass
    # picasso addon will handle this part
    [ "${bds_k8s_datafabriccluster}" == "true" ] && return 0

    # To be compliant with DNS-1123, replace . with -
    local SC_NAME=${bds_storage_maprclustername//./-}

    if [ "${bdshared_storage_localfstype}" = "ext_mapr" ]; then
        bootstrap_setup_ext_mapr_csi
        return 0
    fi

    # Change the secret yaml file
    CSI_USER=$(echo -n "$MAPR_USER" | base64)
    CSI_PASS=$(cat $HOST_MAPR_CONF_DIR/mapr-pass | base64)
    SERVICE_TICKET=$(cat $HOST_MAPR_CONF_DIR/$MAPR_HCP_SERVICE_TICKET | base64 -w 0)

    util_copy_file $MAPR_TEMPLATES_DIR/secrets-template.yaml $MAPR_TEMPLATES_DIR/secrets.yaml
    log_exec "sed -i 's|@@@@CSI_USER@@@@|$CSI_USER|g' $MAPR_TEMPLATES_DIR/secrets.yaml"
    log_exec "sed -i 's|@@@@CSI_PASS@@@@|$CSI_PASS|g' $MAPR_TEMPLATES_DIR/secrets.yaml"
    log_exec "sed -i 's|@@@@EPIC_SERVICE_TICKET@@@@|$SERVICE_TICKET|g' $MAPR_TEMPLATES_DIR/secrets.yaml"
    log_exec "sed -i 's|@@@@SECRET_NAME_SUFFIX@@@@|$SC_NAME|g' $MAPR_TEMPLATES_DIR/secrets.yaml"

    # Change the storage class yaml
    local CLDB_NODES=""
    local REST_URL=""

    if [ "$bds_ha_enabled" == "Yes" ]
    then
        REST_URL="$HA_ORIGINAL_PRIMARY:8443 $HA_ORIGINAL_SHADOW:8443"
        CLDB_NODES="$HA_ORIGINAL_PRIMARY:7222 $HA_ORIGINAL_SHADOW:7222 $HA_ARBITER:7222"
    else
        REST_URL="$bds_network_controllerip:8443"
        CLDB_NODES="$bds_network_controllerip:7222"
    fi

    util_copy_file $MAPR_TEMPLATES_DIR/storageclass-template.yaml $MAPR_TEMPLATES_DIR/storageclass.yaml
    log_exec "sed -i 's|@@@@SC_NAME@@@@|$SC_NAME|g' $MAPR_TEMPLATES_DIR/storageclass.yaml"
    log_exec "sed -i 's|@@@@DEFAULT_SC_FLAG@@@@|true|g' $MAPR_TEMPLATES_DIR/storageclass.yaml"
    log_exec "sed -i 's|@@@@MAPR_MOUNT_PREFIX@@@@|$MAPR_MOUNT_PREFIX|g' $MAPR_TEMPLATES_DIR/storageclass.yaml"
    log_exec "sed -i 's|@@@@MAPR_REST_SERVERS@@@@|$REST_URL|g' $MAPR_TEMPLATES_DIR/storageclass.yaml"
    log_exec "sed -i 's|@@@@MAPR_CLDB_SERVERS@@@@|$CLDB_NODES|g' $MAPR_TEMPLATES_DIR/storageclass.yaml"
    log_exec "sed -i 's|@@@@K8S_CLUSTER_NAME@@@@|$bds_k8s_clustername|g' $MAPR_TEMPLATES_DIR/storageclass.yaml"
    log_exec "sed -i 's|@@@@MAPR_CLUSTER_NAME@@@@|$bds_storage_maprclustername|g' $MAPR_TEMPLATES_DIR/storageclass.yaml"
    log_exec "sed -i 's|@@@@MAPR_SECURE@@@@|secure|g' $MAPR_TEMPLATES_DIR/storageclass.yaml"
    log_exec "sed -i 's|@@@@SECRET_NAME_SUFFIX@@@@|$SC_NAME|g' $MAPR_TEMPLATES_DIR/storageclass.yaml"

    if [ "$bds_storage_posixclienttype" == "platinum" ]
    then
        log_exec "sed -i 's|@@@@POSIX_CLIENT_TYPE@@@@|true|g' $MAPR_TEMPLATES_DIR/storageclass.yaml"
    else
        log_exec "sed -i 's|@@@@POSIX_CLIENT_TYPE@@@@|false|g' $MAPR_TEMPLATES_DIR/storageclass.yaml"
    fi

    # Apply all the yaml files after changing the repo
    util_copy_file "$MAPR_TEMPLATES_DIR/10_csi-deploy-nodeplugin-template.yaml" "$MAPR_TEMPLATES_DIR/csi/10_csi-deploy-nodeplugin.yaml"
    insert_airgap_repo "$MAPR_TEMPLATES_DIR/csi/10_csi-deploy-nodeplugin.yaml"

    # Delete the csi-deploy-provisioner.yaml/snapshot-crd.yaml used in previous setup
    util_delete_file_no_error "$MAPR_TEMPLATES_DIR/csi/11_csi-deploy-provisioner.yaml"
    util_delete_file_no_error "$MAPR_TEMPLATES_DIR/csi/12_csi-deploy-provisioner.yaml"
    util_delete_file_no_error "$MAPR_TEMPLATES_DIR/csi/13_csi-snapshot-crd.yaml"

    util_copy_file "$MAPR_TEMPLATES_DIR/$(get_csi_deploy_provisioner_template_prefix)_csi-deploy-provisioner-template.yaml" \
                   "$MAPR_TEMPLATES_DIR/csi/$(get_csi_deploy_provisioner_template_prefix)_csi-deploy-provisioner.yaml"
    insert_airgap_repo "$MAPR_TEMPLATES_DIR/csi/$(get_csi_deploy_provisioner_template_prefix)_csi-deploy-provisioner.yaml"

    bootstrap_setup_additional_mapr_csi_crd

    log_exec kubectl -n hpe-csi create -f $MAPR_TEMPLATES_DIR/csi/
    log_exec kubectl -n hpe-csi create -f $MAPR_TEMPLATES_DIR/secrets.yaml
    log_exec kubectl create -f $MAPR_TEMPLATES_DIR/storageclass.yaml

    log_exec kubectl create namespace $MAPR_EXTERNAL_INFO_NS

    # Fetch mapr-external-secrets file from the controller
    generate_ext_secrets
    if [ -f "$HOST_MAPR_CONF_DIR/$MAPR_EXTERNAL_SECRETS" ]
    then
        log_exec kubectl -n $MAPR_EXTERNAL_INFO_NS create -f $HOST_MAPR_CONF_DIR/$MAPR_EXTERNAL_SECRETS
    fi
}

bootstrap_master() {
    bootstrap_setup_network
    bootstrap_setup_mapr_csi
}

install_start_kube() {

    install_config_selinux_items

    # In case of SLES or OpenSUSE, K8S packages are provided from respective SLES CAASP repo or OpenSUSE repo
    # No need to generate k8s repo file for SUSE if it is not airgap mode
    [[ "${OS_FAMILY}" == "centos" ]] && install_configure_k8s_yum_repo
    [[ "${OS_FAMILY}" == "suse"  && -n "$bds_k8s_containerrepo" ]] &&          \
        install_configure_k8s_yum_repo

    ADD_INSTALL_PKGS=""
    [[ "${OS_FAMILY}" == 'centos' ]] && ADD_INSTALL_PKGS="etcd"
    util_rpm_install ${ADD_INSTALL_PKGS} $(get_rpms)

    if [[ $? -ne 0 ]]; then
        log_error "Failed to install kubernetes rpms."
        exit 101
    fi

    # SUSE K8S package installs cri-o and enables it
    # HPE-CP uses docker engine-runtime, so disable cri-o
    if [[ "${OS_FAMILY}" == 'suse' ]]
    then
        util_chkconfig_off crio
        util_stop_services crio
        log_sudo_exec_no_exit sed "/^Wants=.*/d" -i /usr/lib/systemd/system/kubelet.service
        log_sudo_exec_no_exit sed "/^Restart=.*/d" -i /usr/lib/systemd/system/crio.service
        util_config_line_replace_no_error /etc/sysconfig/kubelet '^KUBELET_EXTRA_ARGS=.*' 'KUBELET_EXTRA_ARGS='
    fi

    log_sudo_exec systemctl daemon-reload
    util_chkconfig_on kubelet
    util_start_services kubelet

    # docker credentials file needs to be in /root/.docker before kubeadm starts
    setup_root_docker_creds

    # Check to see if we are the first master, in which case we have to create
    # config for kubeadm
    if [ "$bds_k8s_purpose" == "master" ]
    then
        # unset proxy variables
        export http_proxy=
        export https_proxy=
        export no_proxy=

        cat << EOF > /etc/bluedata/k8s-audit-policy.yaml
apiVersion: audit.k8s.io/v1beta1
kind: Policy
rules:
- level: Metadata
EOF
        # As a note to future reviewers: these numbers are 10x the suggested
        # config here:
        # https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#eventratelimit
        cat << EOF > /etc/bluedata/k8s-event-config.yaml
apiVersion: eventratelimit.admission.k8s.io/v1alpha1
kind: Configuration
limits:
- type: Namespace
  qps: 500
  burst: 1000
  cacheSize: 20000
- type: User
  qps: 100
  burst: 500
EOF

        # Turns out that AdmissionConfiguration went v1 in 1.17, so we need to ensure that 1.15-1.16
        # use the alpha version of AdmissionConfiguration
        admissionConfigVersion=""

        if [[ "$bds_k8s_version" == *"1.15."* || "$bds_k8s_version" == *"1.16."* ]]; then
            admissionConfigVersion="apiserver.k8s.io/v1alpha1"
        else
            admissionConfigVersion="apiserver.config.k8s.io/v1"
        fi

        # This file stolen from
        # https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#eventratelimit
        cat << EOF > /etc/bluedata/k8s-admission-control-config.yaml
apiVersion: $admissionConfigVersion
kind: AdmissionConfiguration
plugins:
- name: EventRateLimit
  path: /etc/bluedata/k8s-event-config.yaml
EOF

        KUBEADM_API_VER=$(get_kubeadm_api_version)
        log_sudo_exec mkdir -p "/etc/kubernetes/pki"
        # Check to see if we are the first master or secondary master(s).
        # We expect the full join command and the certificate key to be passed.
        # We expect this to be passed in as env
        if [ -z "$K8S_CERTIFICATE_KEY" ]
        then
            # sles
            # use hyperkube image in OpenSUSE K8S repo
            # https://registry.opensuse.org/cgi-bin/cooverview
            # SLES Caasp repo provides ONLY hyperkube image to setup k8s pods
            # https://documentation.suse.com/external-tree/en-us/suse-caasp/4/skuba-cluster-images.txt

            useHyperKubeImage=true

            MAJOR_VER=$(echo $bds_k8s_version | cut -d"." -f1)
            MINOR_VER=$(echo $bds_k8s_version | cut -d"." -f2)
            # All k8s versions >= 1.18 receive the below setting.
            [[ "$MAJOR_VER" -eq 1 && "$MINOR_VER" -ge 18 ]] && useHyperKubeImage=false
            [[ "$MAJOR_VER" -gt 1 ]] && useHyperKubeImage=false
            create_encryption_secret

            cat << EOF > /tmp/kubeadm-config.yaml
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
failSwapOn: false
---
apiVersion: $KUBEADM_API_VER
kind: ClusterConfiguration
useHyperKubeImage: $useHyperKubeImage
kubernetesVersion: "$bds_k8s_version"
controlPlaneEndpoint: "$bds_k8s_gatewayhost:$bds_k8s_gatewayport"
etcd:
  local:
    extraArgs:
      quota-backend-bytes: "8589934592"
      auto-compaction-retention: "24h"
      auto-compaction-mode: "periodic"
networking:
  serviceSubnet: $bds_k8s_servicenetworkrange
  podSubnet: $bds_k8s_podnetworkrange
  dnsDomain: $bds_k8s_dnsdomain
controllerManager:
  extraArgs:
    "node-cidr-mask-size": "25"
    profiling: "false"
    feature-gates: "RotateKubeletServerCertificate=true"
    terminated-pod-gc-threshold: "10"
scheduler:
  extraArgs:
    profiling: "false"
clusterName: $bds_k8s_clustername
apiServer:
  timeoutForControlPlane: 10m0s
  extraArgs:
    requestheader-allowed-names: ""
    runtime-config : "settings.k8s.io/v1alpha1=true"
    enable-admission-plugins : PodPreset,NodeRestriction,PodSecurityPolicy,EventRateLimit,AlwaysPullImages
    admission-control-config-file: "/etc/bluedata/k8s-admission-control-config.yaml"
    advertise-address: $bds_network_primaryip
    audit-policy-file: "/etc/bluedata/k8s-audit-policy.yaml"
    audit-log-path: "/var/log/bluedata/k8s-audit.log"
    audit-log-maxage: "30"
    audit-log-maxbackup: "10"
    audit-log-maxsize: "1024"
    api-audiences: api,istio-ca
    service-account-issuer: kubernetes.default.svc
    service-account-key-file: /etc/kubernetes/pki/sa.key
    service-account-signing-key-file: /etc/kubernetes/pki/sa.key
    profiling: "false"
    encryption-provider-config: /etc/kubernetes/pki/encryption.yaml
    tls-cipher-suites: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
  extraVolumes:
  - name: logs
    hostPath: /var/log/bluedata
    mountPath: /var/log/bluedata
    readOnly: false
    pathType: Directory
  - name: audit-policy
    hostPath: /etc/bluedata/k8s-audit-policy.yaml
    mountPath: /etc/bluedata/k8s-audit-policy.yaml
    readOnly: true
    pathType: File
  - name: event-rate-policy
    hostPath: /etc/bluedata/k8s-event-config.yaml
    mountPath: /etc/bluedata/k8s-event-config.yaml
    readOnly: true
    pathType: File
  - name: admission-control-policy
    hostPath: /etc/bluedata/k8s-admission-control-config.yaml
    mountPath: /etc/bluedata/k8s-admission-control-config.yaml
    readOnly: true
    pathType: File
EOF
            # If airgap enabled then set the docker repo in /tmp/kubeadm-config.yaml
            if [ -n "$bds_k8s_containerrepo" ]
            then
                if [[ "${bds_global_osname}" == "sles" ]]
                then
                    build_package_names ${bds_k8s_version}
                    IMAGE_REPO="${bds_k8s_caascontainerrepo}/registry.suse.com/caasp/$K8S_CAASP_VERSION"
                    ETCD_VERSION=$(get_etcd_version_for_sles "${bds_k8s_version}")
                    cat << EOF >> /tmp/kubeadm-config.yaml
etcd:
  local:
    imageTag: "${ETCD_VERSION}"
EOF
                else
                    IMAGE_REPO="${bds_k8s_containerrepo}/k8s.gcr.io"
                fi
                cat << EOF >> /tmp/kubeadm-config.yaml
imageRepository: $IMAGE_REPO
EOF
            elif [[ -z "$bds_k8s_containerrepo" && "${bds_global_osname}" == "sles" ]]
            then
                build_package_names ${bds_k8s_version}
                ETCD_VERSION=$(get_etcd_version_for_sles "${bds_k8s_version}")
                # If airgap is not set and os is sles, set sles caasp repository
                cat << EOF >> /tmp/kubeadm-config.yaml
etcd:
  local:
    imageTag: "${ETCD_VERSION}"
imageRepository: "registry.suse.com/caasp/$K8S_CAASP_VERSION"
EOF
            fi

            CERTS_OPTION=$(get_certs_option)

            log_sudo_exec kubeadm init $KUBEADM_SWAP_OPTION --config=/tmp/kubeadm-config.yaml $CERTS_OPTION -v=10
            # This needs to happen after kubeadm init because that's when /var/lib/kubelet is created
            setup_kubelet_docker_creds

            # Set systemReserved in /var/lib/kubelet/config.yaml
            set_system_reserved 0.1

            setup_kubeconfig
            # bootstrap master
            bootstrap_master
        else
            CONTROL_PLANE=$(get_control_plane_option)
            # Move encryption config created by master from tmp location into it's rightful location.
            log_sudo_exec mv /opt/bluedata/tmp/encryption.yaml /etc/kubernetes/pki
            log_sudo_exec "chmod 600 /etc/kubernetes/pki/encryption.yaml"
            log_sudo_exec $K8S_JOIN_COMMAND $KUBEADM_SWAP_OPTION $CONTROL_PLANE --certificate-key $K8S_CERTIFICATE_KEY  -v=10
            setup_kubelet_docker_creds
            # Set systemReserved in /var/lib/kubelet/config.yaml
            set_system_reserved 0.1
            setup_kubeconfig
        fi

        setup_hpecp_plugin

        install_update_cert_permissions

        kubernetes_manifest_file_perms
    else
        # Worker node, just use the join command
        log_sudo_exec $K8S_JOIN_COMMAND $KUBEADM_SWAP_OPTION -v=10

        setup_kubelet_docker_creds

        # Set systemReserved in /var/lib/kubelet/config.yaml
        set_system_reserved 0.1
    fi

    [[ -d "/var/lib/etcd" ]] && log_sudo_exec "chmod 700 /var/lib/etcd"

    extra_kubelet_config

    set_kubelet_flags

    set_kubelet_sysctl

    restart_kubelet

    return 0
}

install_rollback_kube() {
    [[ "${ROLLBACK_ON_ERROR}" == 'false' ]] && return 0

    log_sudo_exec_no_exit kubeadm reset --ignore-preflight-errors all --force -v=10

    util_stop_services kubelet || true
    util_chkconfig_off kubelet || true
    util_delete_file_no_error -r ~/.kube

    util_sudo_delete_file /etc/sysctl.d/k8s.conf

    log_sudo_exec sysctl --system

    ADD_REMOVE_PKGS=""
    [[ "${OS_FAMILY}" == 'suse' ]] && ADD_REMOVE_PKGS=cri-o

    util_rpm_erase_no_exit $(get_rpms) $ADD_REMOVE_PKGS

    clean_non_epic_containers

    clean_non_epic_images

    delete_fsmounts

    # If iptables are enabled, reset all rules and re-create our rules
    if [ "$bds_prechecks_iptables" == "true" ]
    then
        util_restart_services firewalld

        # Lets wait for firewalld to be up and running
        # XXX FIXME
        sleep 30

        log_exec_no_exit "$OvsUtil createfwrules"
    fi

    # Restart docker as well
    util_restart_services docker

    util_sudo_delete_file_no_error -r \
        /var/lib/etcd /etc/kubernetes/manifests/ /etc/kubernetes/pki \
        /etc/kubernetes/admin.conf /etc/kubernetes/kubelet.conf \
        /etc/kubernetes/bootstrap-kubelet.conf /etc/kubernetes/controller-manager.conf /etc/kubernetes/scheduler.conf \
        /var/lib/kubelet /etc/cni/net.d /var/lib/dockershim /var/run/kubernetes /var/lib/cni \
        ${HOST_MAPR_CONF_DIR}/${bds_k8s_clustername}-pass ${HOST_MAPR_CONF_DIR}/${bds_k8s_clustername}-ticket \
        ${OPSYS_YUM_REPO_BASE}/bd-kubernetes.repo /etc/sysconfig/kubelet

    log_sudo_exec_no_exit ip link delete flannel.1

    return 0
}

install_finalize_kube() {
    return 0
}

upgrade_stop_kube() {
    return 0
}

upgrade_prepare_kube() {
    return 0
}

upgrade_kubelet_kubectl() {
    build_package_names ${K8S_UPGRADE_VERSION}
    upgrade_package ${K8S_KUBELET}
    upgrade_package ${K8S_KUBECTL}
    restart_kubelet
}

upgrade_package() {
    package=$1
    log_file "Upgrading $package to version ${K8S_UPGRADE_VERSION}"
    if [[ "${OS_FAMILY}" == "centos" ]]
    then
        package_name="${package}-${K8S_UPGRADE_VERSION}-0"
        util_rpm_install $package_name --disablerepo=* --enablerepo=kubernetes
    else
        package_name="${package}-${K8S_UPGRADE_VERSION}"
        util_rpm_install $package_name
    fi
    if [[ $? -ne 0 ]]; then
        log_error "Failed to upgrade $package."
        exit 101
    fi
}

create_encryption_secret() {
    cat << EOF > /tmp/encryption.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
    - secrets
    providers:
    - aescbc:
        keys:
        - name: key1
          secret: $(head -c 32 /dev/urandom | base64)
    - identity: {}
EOF

    util_sudo_move_file /tmp/encryption.yaml "/etc/kubernetes/pki/encryption.yaml"
    log_sudo_exec "chown root:root /etc/kubernetes/pki/encryption.yaml"
    log_sudo_exec "chmod 600 /etc/kubernetes/pki/encryption.yaml"

    if [ "$bds_prechecks_selinux" == 'true' ]; then
        ## container-selinux rpm is not available on SLES yet. We are working
        ## with SuSE as of 6/8/2020. So use the default label defined by the
        ## targeted policy until then.
        if [[ ${OS_FAMILY} == 'suse' ]] && ! $(rpm -q --whatprovides container-selinux >/dev/null);
        then
            TYPE_LABEL="var_lib_t"
        else
            TYPE_LABEL="container_file_t"
        fi

        install_config_selinux_files $TYPE_LABEL "/etc/kubernetes/pki/encryption.yaml"
    fi
}

set_kubelet_sysctl() {
    cat << EOF >> /tmp/90-kubelet.conf
vm.overcommit_memory=1
kernel.panic=10
kernel.panic_on_oops=1
EOF

    util_sudo_move_file /tmp/90-kubelet.conf "/etc/sysctl.d/90-kubelet.conf"
    log_sudo_exec "chown root:root /etc/sysctl.d/90-kubelet.conf"
    log_sudo_exec "chmod 700 /etc/sysctl.d/90-kubelet.conf"
    util_sudo_restorecon "/etc/sysctl.d/90-kubelet.conf"

    log_sudo_exec sysctl --system
}

restart_kubelet() {
    log_file "Restarting kubelet..."
    log_sudo_exec systemctl daemon-reload
    util_restart_services kubelet
}

kubeadm_cm_etcd_update(){
    # In SuSE, etcd version is defined in kubeadm-config Config Map
    # It requires to set the etcd version corresponding to k8s version in kubeadm-config Config Map
    local K8S_VERSION_FOR_ETCD=$1
    if [[ "${OS_FAMILY}" == "suse" ]]
    then
        log_file "Updating etcd version in kubeadmin-config of ConfigMap"
        NEW_ETCD_VERSION=$(get_etcd_version_for_sles "${K8S_VERSION_FOR_ETCD}")
        log_exec "kubectl -n kube-system get cm kubeadm-config -oyaml | sed -e 's/imageTag:.*/imageTag: ${NEW_ETCD_VERSION}/' | kubectl replace -f -"
    fi
}

kubeadm_upgrade_apply() {
    log_exec "kubeadm_cm_etcd_update ${K8S_UPGRADE_VERSION}"
    upgrade_command="kubeadm upgrade apply $K8S_UPGRADE_VERSION -y"
    log_file "Executing K8s upgrade command: $upgrade_command"
    log_sudo_exec $upgrade_command
}

downgrade_package() {
    package=$1
    downgrade_version=$2
    log_file "Downgrading $package to version $downgrade_version"
    if [[ "${OS_FAMILY}" == "centos" ]]
    then
        package_name="${package}-${downgrade_version}-0"
        util_rpm_downgrade $package_name --disablerepo=* --enablerepo=kubernetes
    else
        package_name="${package}-${downgrade_version}"
        util_rpm_downgrade $package_name
    fi
    if [[ $? -ne 0 ]]; then
        log_error "Failed to downgrade $package."
        exit 101
    fi
}

# For version 1.14.Z return 0
is_upgrade_version_experimental() {
    MAJOR_VER=$(echo $K8S_UPGRADE_VERSION | cut -d"." -f1)
    MINOR_VER=$(echo $K8S_UPGRADE_VERSION | cut -d"." -f2)

    if [ $MAJOR_VER -eq 1 ] && [ $MINOR_VER -eq 14 ];
    then
        return 0
    else
        return 1
    fi
}

kubeadm_upgrade_node_master() {
    upgrade_command="kubeadm upgrade node"
    if is_upgrade_version_experimental;
    then
        upgrade_command+=" experimental-control-plane"
    fi
    log_file "Executing K8s upgrade command: $upgrade_command"
    log_sudo_exec $upgrade_command
}

kubeadm_upgrade_node_worker() {
    upgrade_command="kubeadm upgrade node"
    if is_upgrade_version_experimental;
    then
        upgrade_command+=" config --kubelet-version $K8S_UPGRADE_VERSION"
    fi
    log_file "Executing K8s upgrade command: $upgrade_command"
    log_sudo_exec $upgrade_command
}

kubeadm_downgrade_apply() {
    downgrade_ver=$1
    if [ "$bds_k8s_purpose" == "master" ]
    then
        log_exec "kubeadm_cm_etcd_update ${downgrade_ver}"
        downgrade_command="kubeadm upgrade apply $downgrade_ver -f"
    else
        downgrade_command="kubeadm upgrade node"
        if is_experimental;
        then
            downgrade_command+=" config --kubelet-version $downgrade_ver"
        fi
    fi
    log_file "Executing K8s downgrade command: $downgrade_command"
    log_sudo_exec $downgrade_command
}

set_bdconfig_version() {
    log_exec bdconfig --set "bds_k8s_version=$1"
}

update_airgap_settings_for_upgrade() {

    # In case of SLES or OpenSUSE, K8S packages are provided from respective SLES CAASP repo or OpenSUSE repo
    # No need to generate k8s repo file for SUSE if it is not airgap mode
    [[ "${OS_FAMILY}" == "centos" ]] && install_configure_k8s_yum_repo
    [[ "${OS_FAMILY}" == "suse"  && -n "$bds_k8s_containerrepo" ]] &&          \
        install_configure_k8s_yum_repo

    get_previous_airgap_settings

    if [ -n "$bds_k8s_previouscontainerrepo" ] && [ "$bds_k8s_previousissecurerepo" == 'false' ]; then
       if [ "$bds_k8s_containerrepo" !=  "$bds_k8s_previouscontainerrepo" ]; then
          log_sudo_exec rm -rf /root/.docker/config.json
          log_sudo_exec rm -rf /var/lib/kubelet/config.json
       fi
    fi

    if [ -n "$bds_k8s_previouscaascontainerrepo" ] && [ "$bds_k8s_previouscaasissecurerepo" == 'false' ]; then
       if [ "$bds_k8s_caascontainerrepo" !=  "$bds_k8s_previouscaascontainerrepo" ]; then
          log_sudo_exec rm -rf /root/.docker/config.json
          log_sudo_exec rm -rf /var/lib/kubelet/config.json
       fi
    fi

    setup_kubelet_docker_creds
    setup_root_docker_creds
}

upgrade_configure_kube() {
    log_file "Updating airgap settings"

    update_airgap_settings_for_upgrade

    log_file "K8s Phase: $PHASE"
    log_file "K8s upgrade version: $K8S_UPGRADE_VERSION"
    build_package_names ${K8S_UPGRADE_VERSION}

    if [ "$PHASE" == 'firstMaster' ]; then
        upgrade_package ${K8S_KUBEADM}
        kubeadm_upgrade_apply
    elif [ "$PHASE" == 'otherMaster' ]; then
        upgrade_package ${K8S_KUBEADM}
        kubeadm_upgrade_node_master
    elif [ "$PHASE" == 'upgradeKubelet' ]; then
        upgrade_kubelet_kubectl
        set_bdconfig_version $K8S_UPGRADE_VERSION
    elif [ "$PHASE" == 'upgradeWorker' ]; then
        upgrade_package ${K8S_KUBEADM}
        kubeadm_upgrade_node_worker
        upgrade_kubelet_kubectl
        set_bdconfig_version $K8S_UPGRADE_VERSION
    elif [ "$PHASE" == 'masterRollback' ]; then
        rollback_kube $K8S_UPGRADE_VERSION
    fi
    [[ "${OS_FAMILY}" == 'suse' ]] && util_stop_services crio
    return 0
}

upgrade_start_kube() {
    return 0
}

upgrade_finalize_kube() {
    return 0
}

get_package_version() {
    package=$1
    RPM_VERSION=$(rpm -qi $package | awk -F': ' '/Version/ {print $2}')
    echo $RPM_VERSION
}

upgrade_rollback_kube() {
    rollback_version="$bds_k8s_version"
    rollback_kube $rollback_version

    #if we removed previous creds from /var/lib/kubelet then restore them
    restore_docker_creds_for_airgap
}

rollback_kube() {
    rollback_version=$1
    if [ "$rollback_version" == "latest" ]
    then
        log_error "Cannot determine Kubernetes version to rollback to."
        exit 101
    else
        build_package_names ${rollback_version}
        kubeadm_version=$(get_package_version kubeadm)
        if [ "$kubeadm_version" != "$rollback_version" ]
        then
            kubeadm_downgrade_apply $rollback_version
            downgrade_package ${K8S_KUBEADM} $rollback_version
        fi
        kubectl_version=$(get_package_version kubectl)
        if [ "$kubectl_version" != "$rollback_version" ]
        then
            downgrade_package ${K8S_KUBECTL} $rollback_version
        fi
        kubelet_version=$(get_package_version kubelet)
        if [ "$kubelet_version" != "$rollback_version" ]
        then
            downgrade_package ${K8S_KUBELET} $rollback_version
            restart_kubelet
        fi
    fi
    [[ "${OS_FAMILY}" == 'suse' ]] && util_stop_services crio
    set_bdconfig_version $rollback_version
    return 0
}

if [ "$PLHA" == 'false' ]; then
    ${MODE}_${STEP}_kube
else
    # Modify code here if the components should handle PLHA related
    # (re)configuration.
    exit 0
fi