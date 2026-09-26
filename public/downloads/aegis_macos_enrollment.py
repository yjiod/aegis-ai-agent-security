"""Native system enrollment. Credentials only; policy changes use signed updates."""
import http.client
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request

from aegis_macos_configuration import (ConfigurationError, existing_state, read_config,
                                      require_no_acl, validate_config, validate_url, write_config)
from aegis_macos_maintenance import MaintenanceError, directory

MAX_RESPONSE_BYTES = 4 * 1024 * 1024
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]{1,32})?")


class EnrollmentError(ValueError):
    """Fixed status, never response content or credentials."""


def checked_url(url):
    return validate_url(url)


def origin(url):
    value = checked_url(url)
    return value.scheme, value.hostname.lower(), value.port or 443


def response_config(value, report_url, device_id):
    required = {"schema", "report_url", "report_token", "signing_secret", "device_id"}
    optional = {"policy", "policy_version", "ed25519_public", "ed25519_key_id"}
    if (not isinstance(value, dict) or not required <= set(value) or set(value) - required - optional
            or value.get("schema") != "aegis.enrollment/v1" or value.get("device_id") != device_id
            or value.get("report_url") != report_url):
        raise EnrollmentError("invalid_enrollment_response")
    return validate_config({"schema": "aegis.reporting/v1", **{key: value[key]
        for key in ("report_url", "report_token", "signing_secret")}})


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise EnrollmentError("enrollment_redirect_refused")


def request_config(enroll_url, report_url, device_id, version, enrollment_key=""):
    if origin(enroll_url) != origin(report_url):
        raise EnrollmentError("enrollment_origin_mismatch")
    if not isinstance(enrollment_key, str) or (enrollment_key and (not 32 <= len(enrollment_key) <= 4096
                           or any(not 33 <= ord(c) <= 126 for c in enrollment_key))):
        raise EnrollmentError("invalid_enrollment_key")
    headers = {"Content-Type": "application/json", "Accept": "application/json", "Accept-Encoding": "identity"}
    if enrollment_key:
        headers["X-Aegis-Enrollment-Key"] = enrollment_key
    request = urllib.request.Request(enroll_url, method="POST", headers=headers,
        data=json.dumps({"device_id": device_id, "agent_version": version}, separators=(",", ":")).encode())
    opener = urllib.request.build_opener(NoRedirect())  # Default verified HTTPS context.
    try:
        with opener.open(request, timeout=25) as response:
            if response.status != 200 or response.geturl() != enroll_url:
                raise EnrollmentError("enrollment_response_refused")
            if response.headers.get_content_type() != "application/json":
                raise EnrollmentError("enrollment_content_type_refused")
            if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                raise EnrollmentError("enrollment_encoding_refused")
            lengths = response.headers.get_all("Content-Length", [])
            if len(lengths) > 1 or (lengths and (not re.fullmatch(r"[0-9]{1,8}", lengths[0])
                                               or int(lengths[0]) > MAX_RESPONSE_BYTES)):
                raise EnrollmentError("enrollment_size_refused")
            data = response.read(MAX_RESPONSE_BYTES + 1)
            if len(data) > MAX_RESPONSE_BYTES or (lengths and len(data) != int(lengths[0])):
                raise EnrollmentError("enrollment_size_refused")
    except EnrollmentError:
        raise
    except urllib.error.HTTPError as exc:
        exc.close()
        raise EnrollmentError("enrollment_unavailable") from None
    except (OSError, urllib.error.URLError, http.client.HTTPException):
        raise EnrollmentError("enrollment_unavailable") from None
    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise EnrollmentError("invalid_enrollment_response")
            value[key] = item
        return value
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=unique_object)
    except (ValueError, UnicodeError, RecursionError):
        raise EnrollmentError("invalid_enrollment_response") from None
    return response_config(value, report_url, device_id)


def configure(root, collector_url, enroll_url, device_id, interval, token, version,
              owner=0, enrollment_key=""):
    if token:
        raise EnrollmentError("use_protected_configuration_for_manual_credentials")
    if (not isinstance(device_id, str) or not re.fullmatch(r"[0-9a-f]{12}", device_id)
            or not isinstance(interval, str) or not re.fullmatch(r"[0-9]{1,5}", interval)
            or not 60 <= int(interval) <= 86400 or not isinstance(version, str) or not VERSION.fullmatch(version)):
        raise EnrollmentError("invalid_enrollment_parameters")
    checked_url(collector_url)
    report_url = collector_url.rstrip("/") + "/v1/reports"
    if origin(enroll_url) != origin(report_url):
        raise EnrollmentError("enrollment_origin_mismatch")
    with directory(root) as parent:
        info = os.fstat(parent)
        if info.st_uid != owner or info.st_mode & 0o022:
            raise EnrollmentError("unsafe_install_directory")
        require_no_acl(parent)
        before = existing_state(parent, owner)
    if before is not None:
        try:
            current = read_config(Path(root) / "reporting.json", owner)
        except ConfigurationError as exc:
            if str(exc) not in {"invalid_json", "duplicate_field", "invalid_contract", "invalid_url",
                                "invalid_credentials", "independent_credentials_required", "configuration_too_large"}:
                raise
        else:
            if current["report_url"] != report_url:
                raise EnrollmentError("server_migration_required")
            return "preserved_health_pending"
    value = request_config(enroll_url, report_url, device_id, version, enrollment_key)
    status = write_config(root, value, owner, expected_state=before)
    return "configured_health_pending" if status == "applied" else status


def selftest():
    value = {"schema": "aegis.enrollment/v1", "report_url": "https://aegis.example.test/aegis/v1/reports",
             "report_token": "synthetic-token-" * 4, "signing_secret": "synthetic-secret-" * 4,
             "device_id": "012345abcdef"}
    return response_config(value, value["report_url"], value["device_id"])["report_token"] == value["report_token"]


def main(argv, runtime_root):
    result = {"schema": "aegis.enrollment-result/v1", "applied": False, "health_verified": False}
    code = 1
    try:
        if sys.platform != "darwin" or os.geteuid() != 0:
            raise EnrollmentError("administrator_required")
        if len(argv) != 7 or Path(argv[0]) != Path(runtime_root):
            raise EnrollmentError("invalid_install_destination")
        key = os.environ.pop("AEGIS_ENROLLMENT_SECRET", "")
        result["status"] = configure(*argv, enrollment_key=key)
        result["applied"] = result["status"] in {"configured_health_pending", "applied_durability_unconfirmed"}
        code = 0 if result["status"] in {"configured_health_pending", "preserved_health_pending"} else 1
    except (EnrollmentError, ConfigurationError) as exc:
        result["status"] = str(exc)
    except (OSError, ValueError, TypeError, MaintenanceError):
        result["status"] = "enrollment_state_unavailable"
    print(json.dumps(result, separators=(",", ":")))
    return code
