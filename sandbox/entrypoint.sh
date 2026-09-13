#!/usr/bin/env bash
set -e

TIMEOUT_SECONDS="${DETONATION_TIMEOUT:-90}"
INPUT_FILE="/sandbox/input/sample.bin"
WORK_DIR="/sandbox/work"
OUTPUT_DIR="/sandbox/output"
LOG_FILE="${OUTPUT_DIR}/detonation.log"
SUMMARY_FILE="${OUTPUT_DIR}/run_summary.json"
ARTIFACTS_ZIP="${OUTPUT_DIR}/artifacts.zip"

echo "[*] Detonation Sandbox Initialized at $(date -u +"%Y-%m-%dT%H:%M:%SZ")" | tee -a "${LOG_FILE}"
echo "[*] Configured Detonation Window: ${TIMEOUT_SECONDS} seconds" | tee -a "${LOG_FILE}"

if [ ! -f "${INPUT_FILE}" ]; then
    echo "[!] Error: No sample found at ${INPUT_FILE}" | tee -a "${LOG_FILE}"
    exit 1
fi

# Prepare working copy of the sample
cp "${INPUT_FILE}" "${WORK_DIR}/sample"
chmod +x "${WORK_DIR}/sample"

# Determine file type
SAMPLE_TYPE=$(file -b "${WORK_DIR}/sample" 2>/dev/null || echo "Unknown")
echo "[*] Detected Sample Type: ${SAMPLE_TYPE}" | tee -a "${LOG_FILE}"

START_TIME=$(date +%s)

# Execute sample in background under its own process group
echo "[*] Launching sample execution..." | tee -a "${LOG_FILE}"

cd "${WORK_DIR}"
if echo "${SAMPLE_TYPE}" | grep -qi "python"; then
    python3 "${WORK_DIR}/sample" >> "${LOG_FILE}" 2>&1 &
elif echo "${SAMPLE_TYPE}" | grep -qiE "shell|bash|sh script"; then
    /bin/bash "${WORK_DIR}/sample" >> "${LOG_FILE}" 2>&1 &
else
    "${WORK_DIR}/sample" >> "${LOG_FILE}" 2>&1 &
fi
SAMPLE_PID=$!

echo "[*] Sample launched with PID: ${SAMPLE_PID}" | tee -a "${LOG_FILE}"

# Monitor execution loop until timeout
ELAPSED=0
while [ "${ELAPSED}" -lt "${TIMEOUT_SECONDS}" ]; do
    sleep 2
    ELAPSED=$(($(date +%s) - START_TIME))
    
    # Check if process or child processes are active
    ACTIVE_PROCS=$(pgrep -P "${SAMPLE_PID}" 2>/dev/null || true)
    if ! kill -0 "${SAMPLE_PID}" 2>/dev/null && [ -z "${ACTIVE_PROCS}" ]; then
        echo "[*] Sample and child processes exited naturally after ${ELAPSED} seconds." | tee -a "${LOG_FILE}"
        break
    fi
done

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
echo "[*] Execution phase completed in ${DURATION}s. Initiating forensic triage..." | tee -a "${LOG_FILE}"

# Terminate sample and spawned child processes
kill -9 "${SAMPLE_PID}" 2>/dev/null || true
pkill -9 -P "${SAMPLE_PID}" 2>/dev/null || true

# Export raw dropped files from staging paths
mkdir -p "${OUTPUT_DIR}/dropped"
find /tmp /var/tmp /dev/shm -maxdepth 3 -type f 2>/dev/null | while read -r f; do
    rel_path=$(echo "$f" | sed 's|^/||')
    dest_dir="${OUTPUT_DIR}/dropped/$(dirname "$rel_path")"
    mkdir -p "$dest_dir"
    cp "$f" "${OUTPUT_DIR}/dropped/$rel_path" 2>/dev/null || true
done

# Extract Forensic Artifacts via Velociraptor
TMP_COLLECT_DIR=$(mktemp -d)
mkdir -p "${TMP_COLLECT_DIR}/artifacts"

if command -v velociraptor >/dev/null 2>&1; then
    echo "[*] Running standalone Velociraptor artifact collection..." | tee -a "${LOG_FILE}"
    velociraptor artifacts collect \
        Linux.Sys.Processes \
        Linux.Sys.Crontab \
        Linux.Sys.Systemd \
        Linux.Search.FileFinder --args Linux.Search.FileFinder.UploadPath="/tmp/**,/var/tmp/**,/etc/cron*/**" \
        --output "${ARTIFACTS_ZIP}" 2>&1 | tee -a "${LOG_FILE}" || true
else
    echo "[!] Velociraptor CLI not found, falling back to native Linux artifact extraction..." | tee -a "${LOG_FILE}"
fi

# Fallback / Supplemental Native Triage if artifacts.zip was not created or needs extra baseline data
if [ ! -f "${ARTIFACTS_ZIP}" ] || [ ! -s "${ARTIFACTS_ZIP}" ]; then
    echo "[*] Generating native fallback triage archive..." | tee -a "${LOG_FILE}"
    mkdir -p "${TMP_COLLECT_DIR}/native"
    
    # Process tree snapshot
    ps aux --forest > "${TMP_COLLECT_DIR}/native/processes.txt" 2>&1 || true
    
    # Cron persistence
    ls -la /etc/cron* > "${TMP_COLLECT_DIR}/native/crontabs.txt" 2>&1 || true
    crontab -l > "${TMP_COLLECT_DIR}/native/user_crontab.txt" 2>&1 || true
    
    # File modifications in common drop locations
    find /tmp /var/tmp /dev/shm -maxdepth 3 -ls > "${TMP_COLLECT_DIR}/native/dropped_files.txt" 2>&1 || true
    
    # Network sockets (attempted or listening)
    netstat -tulpn > "${TMP_COLLECT_DIR}/native/netstat.txt" 2>&1 || ss -tulpn > "${TMP_COLLECT_DIR}/native/netstat.txt" 2>&1 || true
    
    cd "${TMP_COLLECT_DIR}"
    zip -r "${ARTIFACTS_ZIP}" native/ >/dev/null 2>&1 || tar -czf "${OUTPUT_DIR}/artifacts.tar.gz" native/
fi

rm -rf "${TMP_COLLECT_DIR}"

# Write Run Summary JSON
cat <<EOF > "${SUMMARY_FILE}"
{
  "start_time": "${START_TIME}",
  "end_time": "${END_TIME}",
  "duration_seconds": ${DURATION},
  "timeout_seconds": ${TIMEOUT_SECONDS},
  "sample_type": "${SAMPLE_TYPE}",
  "pid": ${SAMPLE_PID},
  "status": "completed"
}
EOF

echo "[*] Detonation Sandbox run finished successfully." | tee -a "${LOG_FILE}"
exit 0
