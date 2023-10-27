#!/bin/sh

set -e

# shellcheck disable=SC2068
version() { IFS="."; printf "%03d%03d%03d\\n" $@; unset IFS;}

# Copy the terraform binary and providers to the mirror to be embedded in the installer binary.
copy_terraform_to_mirror() {
  TARGET_OS_ARCH=$(go env GOOS)_$(go env GOARCH)

  # Clean the mirror, but preserve the README file.
  rm -rf "${PWD}"/pkg/terraform/providers/mirror/*/

  # Copy local terraform providers into data
  find "${PWD}/terraform/bin/${TARGET_OS_ARCH}/" -maxdepth 1 -name "terraform-provider-*.zip" -exec bash -c '
      providerName="$(basename "$1" | cut -d '-' -f 3 | cut -d '.' -f 1)"
      targetOSArch="$2"
      dstDir="${PWD}/pkg/terraform/providers/mirror/openshift/local/$providerName"
      mkdir -p "$dstDir"
      echo "Copying $providerName provider to mirror"
      cp "$1" "$dstDir/terraform-provider-${providerName}_1.0.0_${targetOSArch}.zip"
    ' shell {} "${TARGET_OS_ARCH}" \;

  mkdir -p "${PWD}/pkg/terraform/providers/mirror/terraform/"
  cp "${PWD}/terraform/bin/${TARGET_OS_ARCH}/terraform" "${PWD}/pkg/terraform/providers/mirror/terraform/"
}

# Define cluster api base directories.
TARGET_OS_ARCH=$(go env GOOS)_$(go env GOARCH)
CLUSTER_API_BIN_DIR="${PWD}/cluster-api/bin/${TARGET_OS_ARCH}"
mkdir -p "${CLUSTER_API_BIN_DIR}"
CLUSTER_API_MIRROR_DIR="${PWD}/pkg/cluster-api/mirror/"
mkdir -p "${CLUSTER_API_MIRROR_DIR}"

copy_cluster_api_to_mirror() {
  # Clean the mirror, but preserve the README file.
  rm -rf "${CLUSTER_API_MIRROR_DIR:?}/*.zip"

  sync_envtest

  # Zip every binary in the folder into a single zip file.
  zip -j1 "${CLUSTER_API_MIRROR_DIR}/cluster-api.zip" "${CLUSTER_API_BIN_DIR}"/*
}

envtest_k8s_version="1.28.0"
envtest_arch=$(go env GOOS)-$(go env GOARCH)
sync_envtest() {
  if [ -f "${CLUSTER_API_BIN_DIR}/kube-apiserver" ]; then
    version=$("${CLUSTER_API_BIN_DIR}/kube-apiserver" --version || echo "Kubernetes v0.0.0")
    echo "Found envtest binaries with version: ${version}"
    if [ "${version}" = "Kubernetes v${envtest_k8s_version}" ]; then
      return
    fi
  fi

  bucket="https://storage.googleapis.com/kubebuilder-tools"
  tar_file="kubebuilder-tools-${envtest_k8s_version}-${envtest_arch}.tar.gz"
  dst="${CLUSTER_API_BIN_DIR}/${tar_file}"
  if ! [ -f "${CLUSTER_API_BIN_DIR}/${tar_file}" ]; then
    echo "Downloading envtest binaries"
    curl -fL "${bucket}/${tar_file}" -o "${dst}"
  fi
  tar -C "${CLUSTER_API_BIN_DIR}" -xzf "${dst}" --strip-components=2
  rm "${dst}" # Remove the tar file.
  rm "${CLUSTER_API_BIN_DIR}/kubectl" # Remove kubectl since we don't need it.
}

minimum_go_version=1.20
current_go_version=$(go version | cut -d " " -f 3)

if [ "$(version "${current_go_version#go}")" -lt "$(version "$minimum_go_version")" ]; then
     echo "Go version should be greater or equal to $minimum_go_version"
     exit 1
fi

export CGO_ENABLED=0
MODE="${MODE:-release}"
# build terraform binaries before setting environment variables since it messes up make
if test "${SKIP_TERRAFORM}" != y
then
  make -j8 -C terraform all
  copy_terraform_to_mirror # Copy terraform parts to embedded mirror.
fi

# build cluster-api binaries before setting environment variables since it messes up make
make -j8 -C cluster-api all
copy_cluster_api_to_mirror

GIT_COMMIT="${SOURCE_GIT_COMMIT:-$(git rev-parse --verify 'HEAD^{commit}')}"
GIT_TAG="${BUILD_VERSION:-$(git describe --always --abbrev=40 --dirty)}"
DEFAULT_ARCH="${DEFAULT_ARCH:-amd64}"
GOFLAGS="${GOFLAGS:--mod=vendor}"
GCFLAGS=""
LDFLAGS="${LDFLAGS} -X github.com/openshift/installer/pkg/version.Raw=${GIT_TAG} -X github.com/openshift/installer/pkg/version.Commit=${GIT_COMMIT} -X github.com/openshift/installer/pkg/version.defaultArch=${DEFAULT_ARCH}"
TAGS="${TAGS:-}"
OUTPUT="${OUTPUT:-bin/openshift-install}"

case "${MODE}" in
release)
	LDFLAGS="${LDFLAGS} -s -w"
	TAGS="${TAGS} release"
	;;
dev)
    GCFLAGS="${GCFLAGS} all=-N -l"
	;;
*)
	echo "unrecognized mode: ${MODE}" >&2
	exit 1
esac

if test "${SKIP_GENERATION}" != y
then
	# this step has to be run natively, even when cross-compiling
	GOOS='' GOARCH='' go generate ./data
fi

if (echo "${TAGS}" | grep -q 'libvirt')
then
	export CGO_ENABLED=1
fi

echo "building openshift-install"

# shellcheck disable=SC2086
echo "building openshift-install"
go build "${GOFLAGS}" -gcflags "${GCFLAGS}" -ldflags "${LDFLAGS}" -tags "${TAGS}" -o "${OUTPUT}" ./cmd/openshift-install
