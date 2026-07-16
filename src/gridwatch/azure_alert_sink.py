"""
Azure Blob Storage integration module for GridWatch.
Handles formatting and uploading alert records to the Azure Blob 'alerts' container.
"""

import os
import json
import uuid
import logging
import ipaddress
from datetime import datetime, timezone
from dotenv import load_dotenv
from azure.storage.blob import BlobServiceClient, ContentSettings

try:
    from gridwatch import config
except ImportError:
    import config

logger = logging.getLogger("gridwatch")


def get_network_zone(ip_str: str) -> str:
    """
    Determine the network zone (DMZ or ICS) for a given IP address.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
        if addr in config.DMZ_SUBNET:
            return "DMZ"
        elif addr in config.ICS_SUBNET:
            return "ICS"
    except ValueError:
        pass
    return "UNKNOWN"


def get_register_address(parsed_packet: dict, default_val: int = 0) -> int:
    """
    Helper to extract a register address (or reference number) from a packet,
    falling back to a default value if not present.
    """
    ref_num = parsed_packet.get("ref_num")
    if ref_num is not None:
        return ref_num
    regs = parsed_packet.get("registers")
    if regs:
        return next(iter(regs))
    return default_val


def send_alert_to_blob(
    rule_id: str,
    severity: str,
    source_ip: str,
    destination_ip: str,
    network_zone: str,
    protocol: str,
    function_code: int,
    register_address: int,
    description: str,
    matched_condition: str | None = None,
) -> str | None:
    """
    Loads connection details from .env, builds a compliant JSON alert record,
    and uploads it to the Azure Blob 'alerts' container.
    """
    load_dotenv()
    connection_string = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
    if not connection_string:
        logger.error("AZURE_STORAGE_CONNECTION_STRING not set in environment.")
        return None

    alert_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    payload = {
        "alert_id": alert_id,
        "rule_id": rule_id,
        "severity": severity.lower(),
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "network_zone": network_zone,
        "protocol": protocol,
        "function_code": function_code,
        "register_address": register_address,
        "description": description,
        "matched_condition": matched_condition
    }

    try:
        blob_service_client = BlobServiceClient.from_connection_string(connection_string)
        container_client = blob_service_client.get_container_client("alerts")
        
        # Try to create container if it doesn't already exist
        try:
            container_client.create_container()
        except Exception:
            pass

        blob_name = f"{rule_id}-{alert_id}.json"
        blob_client = container_client.get_blob_client(blob_name)
        
        json_data = json.dumps(payload, indent=2)
        content_settings = ContentSettings(content_type="application/json")
        
        blob_client.upload_blob(json_data, content_settings=content_settings)
        return alert_id
    except Exception as e:
        logger.error(f"Failed to upload alert to Azure Blob Storage: {e}")
        return None
