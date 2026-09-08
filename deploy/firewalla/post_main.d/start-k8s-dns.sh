#!/bin/bash
# Restores the listener systemd unit and sudoers drop-in after Firewalla
# firmware upgrades wipe /etc.
set -euo pipefail

SRC_DIR="/home/pi/.firewalla/k8s-external-dns"
UNIT_NAME="k8s-external-dns-listener.service"
UNIT_SRC="${SRC_DIR}/${UNIT_NAME}"
UNIT_DST="/etc/systemd/system/${UNIT_NAME}"
SUDOERS_SRC="${SRC_DIR}/sudoers.d/k8s-external-dns"
SUDOERS_DST="/etc/sudoers.d/k8s-external-dns"

if [[ ! -x "${SRC_DIR}/listener" ]]; then
  echo "k8s-external-dns: listener binary missing at ${SRC_DIR}/listener" >&2
  exit 0
fi

if [[ ! -f "${UNIT_SRC}" ]]; then
  echo "k8s-external-dns: unit file missing at ${UNIT_SRC}" >&2
  exit 0
fi

# Restore sudoers before starting the service (needed for firerouter_dns reloads).
if [[ -f "${SUDOERS_SRC}" ]]; then
  if [[ ! -f "${SUDOERS_DST}" ]] || ! cmp -s "${SUDOERS_SRC}" "${SUDOERS_DST}"; then
    install -m 0440 "${SUDOERS_SRC}" "${SUDOERS_DST}"
    if command -v visudo >/dev/null 2>&1; then
      if ! visudo -cf "${SUDOERS_DST}"; then
        echo "k8s-external-dns: sudoers validation failed; removing ${SUDOERS_DST}" >&2
        rm -f "${SUDOERS_DST}"
        exit 1
      fi
    fi
  fi
else
  echo "k8s-external-dns: sudoers template missing at ${SUDOERS_SRC}" >&2
fi

if [[ ! -f "${UNIT_DST}" ]]; then
  cp "${UNIT_SRC}" "${UNIT_DST}"
  systemctl daemon-reload
  systemctl enable "${UNIT_NAME}"
fi

systemctl start "${UNIT_NAME}" || true
