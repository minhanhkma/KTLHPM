from pymisp import PyMISP, MISPEvent
import json
import os
import time
import uuid
from datetime import datetime
import urllib3
import re


# MISP configuration
MISP_URL = "https://10.130.10.135"
MISP_KEY = "DLGywR5PiLYZ4SJaziBq1z6OdpAiuCw6ISygfiY3"
MISP_VERIFYCERT = False
ORG_ID = "1"  # Replace with your organization ID
CREATOR_EMAIL = "admin@admin.tét"  # Replace with your email


# Suricata log file
LOG_FILE = "/var/log/suricata/eve.json"
BUFFER_TIMEOUT = 0.2  # Seconds to wait before flushing buffer


# Initialize MISP connection
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
misp = PyMISP(MISP_URL, MISP_KEY, MISP_VERIFYCERT)


# List of domains to monitor
MONITORED_DOMAINS = ["gooogle.com"]

# List of known malicious MD5 hashes
KNOWN_MD5_HASHES = [
    "efc60be384f4abe2df8507e345452677"  # Example hash from the sample log
        # Another example hash
]


def add_attribute_safely(event, attribute_type, value, comment=""):
    """Safely add an attribute to an event if the value is not empty."""
    if value and str(value).strip():
        try:
            misp.add_attribute(event, {
                "type": attribute_type,
                "value": str(value).strip(),
                "comment": comment
            })
            return True
        except Exception as e:
            print(f"Warning: Could not add attribute {attribute_type}: {str(e)}")
    return False


def process_suricata_alert(event_data):
    try:
        if "alert" not in event_data:
            return
            
        # Create a new MISP event
        event = MISPEvent()
        
        # Set basic event properties
        event.distribution = "0"  # Your organization only
        event.threat_level_id = "2"  # Medium
        event.analysis = "0"  # Initial analysis
        event.org_id = ORG_ID
        event.orgc_id = ORG_ID
        event.uuid = str(uuid.uuid4())
        event.event_creator_email = CREATOR_EMAIL
        
        # Convert timestamp to required format
        timestamp = event_data.get("timestamp", "")
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                event.date = dt.strftime("%Y-%m-%d")
                event.timestamp = str(int(dt.timestamp()))
                event.publish_timestamp = str(int(dt.timestamp()))
                event.sighting_timestamp = str(int(dt.timestamp()))
            except ValueError:
                current_time = int(time.time())
                event.date = datetime.now().strftime("%Y-%m-%d")
                event.timestamp = str(current_time)
                event.publish_timestamp = str(current_time)
                event.sighting_timestamp = str(current_time)
        
        # Enhanced event info with custom rule details
        alert = event_data["alert"]
        proto = event_data.get("proto", "Unknown protocol")
        sid = alert.get("signature_id", "Unknown SID")
        gid = alert.get("gid", "Unknown GID")
        rev = alert.get("rev", "Unknown Rev")
        event.info = (
            f"Suricata Alert: {alert['signature']} "
            f"(SID: {sid}) via {proto}"
        )
        
        # Set additional event properties
        event.published = False
        event.locked = True
        event.proposal_email_lock = True
        event.disable_correlation = False
        event.sharing_group_id = "1"
        
        # Add event to MISP
        new_event = misp.add_event(event, pythonify=True)
        
        # Count attributes for attribute_count
        attribute_count = 0
        
        # Add basic network attributes
        if "src_ip" in event_data and event_data["src_ip"]:
            if add_attribute_safely(new_event, "ip-src", event_data["src_ip"], 
                f"Source IP (port: {event_data.get('src_port', 'unknown')})"):
                attribute_count += 1
            
        if "dest_ip" in event_data and event_data["dest_ip"]:
            if add_attribute_safely(new_event, "ip-dst", event_data["dest_ip"], 
                f"Destination IP (port: {event_data.get('dest_port', 'unknown')})"):
                attribute_count += 1
                
        # Add protocol information
        if proto and proto != "Unknown protocol":
            if add_attribute_safely(new_event, "text", proto, "Protocol"):
                attribute_count += 1
                
        # Add Suricata specific attributes
        if sid and str(sid) != "Unknown SID":
            if add_attribute_safely(new_event, "text", str(sid), "Suricata Signature ID"):
                attribute_count += 1
                
        if gid and str(gid) != "Unknown GID":
            if add_attribute_safely(new_event, "text", str(gid), "Suricata GID"):
                attribute_count += 1
                
        if rev and str(rev) != "Unknown Rev":
            if add_attribute_safely(new_event, "text", str(rev), "Suricata Rule Revision"):
                attribute_count += 1
        
        # Add alert category and signature
        category = alert.get("category")
        if category:
            if add_attribute_safely(new_event, "text", category, "Alert Category"):
                attribute_count += 1
                
        # Add HTTP information if present
        if "http" in event_data:
            http_data = event_data["http"]
            if "hostname" in http_data:
                if add_attribute_safely(new_event, "domain", http_data["hostname"], "HTTP Hostname"):
                    attribute_count += 1
            if "url" in http_data:
                if add_attribute_safely(new_event, "url", http_data["url"], "HTTP URL"):
                    attribute_count += 1
            if "http_user_agent" in http_data:
                if add_attribute_safely(new_event, "text", http_data["http_user_agent"], "HTTP User Agent"):
                    attribute_count += 1
                    
        # Add DNS information if present
        if "dns" in event_data:
            dns_data = event_data["dns"]
            if "rrname" in dns_data:
                if add_attribute_safely(new_event, "domain", dns_data["rrname"], "DNS Query"):
                    attribute_count += 1
            if "rdata" in dns_data:
                if add_attribute_safely(new_event, "domain", dns_data["rdata"], "DNS Response"):
                    attribute_count += 1
                    
        # Add TLS information if present
        if "tls" in event_data:
            tls_data = event_data["tls"]
            if "subject" in tls_data:
                if add_attribute_safely(new_event, "text", tls_data["subject"], "TLS Subject"):
                    attribute_count += 1
            if "issuer" in tls_data:
                if add_attribute_safely(new_event, "text", tls_data["issuer"], "TLS Issuer"):
                    attribute_count += 1
                    
        # Add packet information
        if "packet" in event_data:
            packet_data = event_data["packet"]
            if "payload" in packet_data:
                if add_attribute_safely(new_event, "text", packet_data["payload"], "Packet Payload"):
                    attribute_count += 1
                    
        # Add flow information
        if "flow" in event_data:
            flow_data = event_data["flow"]
            if "source" in flow_data:
                if add_attribute_safely(new_event, "text", flow_data["source"], "Flow Source"):
                    attribute_count += 1
            if "state" in flow_data:
                if add_attribute_safely(new_event, "text", flow_data["state"], "Flow State"):
                    attribute_count += 1
                    
        # Add the full event data as a text attribute for reference
        if add_attribute_safely(new_event, "text", json.dumps(event_data, indent=2), "Full Event Data"):
            attribute_count += 1
        
        # Update event with attribute count
        try:
            latest_event = misp.get_event(new_event.id, pythonify=True)
            latest_event.attribute_count = str(attribute_count)
            misp.update_event(latest_event)
        except Exception as e:
            print(f"Warning: Could not update attribute count: {str(e)}")
            
        print(f"Added event to MISP: {new_event.info}")
        
    except Exception as e:
        print(f"Error processing alert: {str(e)}")


def process_fileinfo_event(event_data):
    try:
        if "fileinfo" not in event_data:
            return
        
        # Validate filename
        fileinfo = event_data["fileinfo"]
        filename = fileinfo.get("filename", "")
        md5_hash = fileinfo.get("md5", "")
        
        # Check if the MD5 hash matches any known malicious hash
        if md5_hash not in KNOWN_MD5_HASHES:
            print(f"MD5 hash {md5_hash} not in known hashes, skipping event.")
            return
        
        # Create a new MISP event
        event = MISPEvent()
        
        # Set basic event properties
        event.distribution = "0"  # Your organization only
        event.threat_level_id = "1"  # High
        event.analysis = "0"  # Initial analysis
        event.org_id = ORG_ID
        event.orgc_id = ORG_ID
        event.uuid = str(uuid.uuid4())
        event.event_creator_email = CREATOR_EMAIL
        
        # Convert timestamp to required format
        timestamp = event_data.get("timestamp", "")
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                event.date = dt.strftime("%Y-%m-%d")
                event.timestamp = str(int(dt.timestamp()))
                event.publish_timestamp = str(int(dt.timestamp()))
                event.sighting_timestamp = str(int(dt.timestamp()))
            except ValueError:
                current_time = int(time.time())
                event.date = datetime.now().strftime("%Y-%m-%d")
                event.timestamp = str(current_time)
                event.publish_timestamp = str(current_time)
                event.sighting_timestamp = str(current_time)
        
        # Enhanced event info with file details
        event.info = f"Malicious File Detected: MD5 {md5_hash}"
        
        # Set additional event properties
        event.published = False
        event.locked = True
        event.proposal_email_lock = True
        event.disable_correlation = False
        event.sharing_group_id = "1"
        
        # Add event to MISP
        new_event = misp.add_event(event, pythonify=True)
        
        # Count attributes for attribute_count
        attribute_count = 0
        
        # Add file attributes
        if "filename" in fileinfo:
            if add_attribute_safely(new_event, "filename", fileinfo["filename"], "File Name"):
                attribute_count += 1
        if "magic" in fileinfo:
            if add_attribute_safely(new_event, "text", fileinfo["magic"], "File Magic"):
                attribute_count += 1
        if "md5" in fileinfo:
            if add_attribute_safely(new_event, "md5", fileinfo["md5"], "File MD5 Hash"):
                attribute_count += 1
        if "sha1" in fileinfo:
            if add_attribute_safely(new_event, "sha1", fileinfo["sha1"], "File SHA1 Hash"):
                attribute_count += 1
        if "sha256" in fileinfo:
            if add_attribute_safely(new_event, "sha256", fileinfo["sha256"], "File SHA256 Hash"):
                attribute_count += 1
        if "size" in fileinfo:
            if add_attribute_safely(new_event, "size-in-bytes", fileinfo["size"], "File Size"):
                attribute_count += 1
        
        # Add the full event data as a text attribute for reference
        if add_attribute_safely(new_event, "text", json.dumps(event_data, indent=2), "Full Event Data"):
            attribute_count += 1
        
        # Update event with attribute count
        try:
            latest_event = misp.get_event(new_event.id, pythonify=True)
            latest_event.attribute_count = str(attribute_count)
            misp.update_event(latest_event)
        except Exception as e:
            print(f"Warning: Could not update attribute count: {str(e)}")
        
        print(f"Added fileinfo event to MISP: {new_event.info}")
        
    except Exception as e:
        print(f"Error processing fileinfo event: {str(e)}")


def process_ssh_event(event_data):
    try:
        if "ssh" not in event_data:
            return
        
        # Create a new MISP event
        event = MISPEvent()
        
        # Set basic event properties
        event.distribution = "0"  # Your organization only
        event.threat_level_id = "2"  # Medium
        event.analysis = "0"  # Initial analysis
        event.org_id = ORG_ID
        event.orgc_id = ORG_ID
        event.uuid = str(uuid.uuid4())
        event.event_creator_email = CREATOR_EMAIL
        
        # Convert timestamp to required format
        timestamp = event_data.get("timestamp", "")
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                event.date = dt.strftime("%Y-%m-%d")
                event.timestamp = str(int(dt.timestamp()))
                event.publish_timestamp = str(int(dt.timestamp()))
                event.sighting_timestamp = str(int(dt.timestamp()))
            except ValueError:
                current_time = int(time.time())
                event.date = datetime.now().strftime("%Y-%m-%d")
                event.timestamp = str(current_time)
                event.publish_timestamp = str(current_time)
                event.sighting_timestamp = str(current_time)
        
        # Enhanced event info with SSH details
        event.info = "SSH Connection Event"
        
        # Set additional event properties
        event.published = False
        event.locked = True
        event.proposal_email_lock = True
        event.disable_correlation = False
        event.sharing_group_id = "1"
        
        # Add event to MISP
        new_event = misp.add_event(event, pythonify=True)
        
        # Count attributes for attribute_count
        attribute_count = 0
        
        # Add basic network attributes
        if "src_ip" in event_data and event_data["src_ip"]:
            if add_attribute_safely(new_event, "ip-src", event_data["src_ip"], 
                f"Source IP (port: {event_data.get('src_port', 'unknown')})"):
                attribute_count += 1
            
        if "dest_ip" in event_data and event_data["dest_ip"]:
            if add_attribute_safely(new_event, "ip-dst", event_data["dest_ip"], 
                f"Destination IP (port: {event_data.get('dest_port', 'unknown')})"):
                attribute_count += 1
        
        # Add protocol information
        proto = event_data.get("proto", "Unknown protocol")
        if proto and proto != "Unknown protocol":
            if add_attribute_safely(new_event, "text", proto, "Protocol"):
                attribute_count += 1
        
        # Add SSH client and server details
        ssh_data = event_data["ssh"]
        if "client" in ssh_data:
            client_data = ssh_data["client"]
            if "proto_version" in client_data:
                if add_attribute_safely(new_event, "text", client_data["proto_version"], "SSH Client Protocol Version"):
                    attribute_count += 1
            if "software_version" in client_data:
                if add_attribute_safely(new_event, "text", client_data["software_version"], "SSH Client Software Version"):
                    attribute_count += 1
        
        if "server" in ssh_data:
            server_data = ssh_data["server"]
            if "proto_version" in server_data:
                if add_attribute_safely(new_event, "text", server_data["proto_version"], "SSH Server Protocol Version"):
                    attribute_count += 1
            if "software_version" in server_data:
                if add_attribute_safely(new_event, "text", server_data["software_version"], "SSH Server Software Version"):
                    attribute_count += 1
        
        # Add the full event data as a text attribute for reference
        if add_attribute_safely(new_event, "text", json.dumps(event_data, indent=2), "Full Event Data"):
            attribute_count += 1
        
        # Update event with attribute count
        try:
            latest_event = misp.get_event(new_event.id, pythonify=True)
            latest_event.attribute_count = str(attribute_count)
            misp.update_event(latest_event)
        except Exception as e:
            print(f"Warning: Could not update attribute count: {str(e)}")
        
        print(f"Added SSH event to MISP: {new_event.info}")
        
    except Exception as e:
        print(f"Error processing SSH event: {str(e)}")


def process_http_event(event_data):
    """Process HTTP events and push logs for specific domains."""
    try:
        if "http" not in event_data:
            return
        
        http_data = event_data["http"]
        hostname = http_data.get("hostname", "")
        
        # Check if the hostname matches any monitored domain
        if not any(re.search(domain, hostname, re.IGNORECASE) for domain in MONITORED_DOMAINS):
            return
        
        # Create a new MISP event
        event = MISPEvent()
        
        # Set basic event properties
        event.distribution = "0"  # Your organization only
        event.threat_level_id = "2"  # Medium
        event.analysis = "0"  # Initial analysis
        event.org_id = ORG_ID
        event.orgc_id = ORG_ID
        event.uuid = str(uuid.uuid4())
        event.event_creator_email = CREATOR_EMAIL
        
        # Convert timestamp to required format
        timestamp = event_data.get("timestamp", "")
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                event.date = dt.strftime("%Y-%m-%d")
                event.timestamp = str(int(dt.timestamp()))
                event.publish_timestamp = str(int(dt.timestamp()))
                event.sighting_timestamp = str(int(dt.timestamp()))
            except ValueError:
                current_time = int(time.time())
                event.date = datetime.now().strftime("%Y-%m-%d")
                event.timestamp = str(current_time)
                event.publish_timestamp = str(current_time)
                event.sighting_timestamp = str(current_time)
        
        # Enhanced event info with HTTP details
        event.info = f"HTTP Event: Access to {hostname}"
        
        # Set additional event properties
        event.published = False
        event.locked = True
        event.proposal_email_lock = True
        event.disable_correlation = False
        event.sharing_group_id = "1"
        
        # Add event to MISP
        new_event = misp.add_event(event, pythonify=True)
        
        # Count attributes for attribute_count
        attribute_count = 0
        
        # Add HTTP attributes
        if "hostname" in http_data:
            if add_attribute_safely(new_event, "domain", http_data["hostname"], "HTTP Hostname"):
                attribute_count += 1
        if "url" in http_data:
            if add_attribute_safely(new_event, "url", http_data["url"], "HTTP URL"):
                attribute_count += 1
        if "http_user_agent" in http_data:
            if add_attribute_safely(new_event, "text", http_data["http_user_agent"], "HTTP User Agent"):
                attribute_count += 1
        if "http_method" in http_data:
            if add_attribute_safely(new_event, "text", http_data["http_method"], "HTTP Method"):
                attribute_count += 1
        if "protocol" in http_data:
            if add_attribute_safely(new_event, "text", http_data["protocol"], "HTTP Protocol"):
                attribute_count += 1
        if "status" in http_data:
            if add_attribute_safely(new_event, "text", str(http_data["status"]), "HTTP Status Code"):
                attribute_count += 1
        
        # Add the full event data as a text attribute for reference
        if add_attribute_safely(new_event, "text", json.dumps(event_data, indent=2), "Full Event Data"):
            attribute_count += 1
        
        # Update event with attribute count
        try:
            latest_event = misp.get_event(new_event.id, pythonify=True)
            latest_event.attribute_count = str(attribute_count)
            misp.update_event(latest_event)
        except Exception as e:
            print(f"Warning: Could not update attribute count: {str(e)}")
        
        print(f"Added HTTP event to MISP: {new_event.info}")
        
    except Exception as e:
        print(f"Error processing HTTP event: {str(e)}")


def process_event(event_data):
    """Process a generic event based on its type."""
    event_type = event_data.get("event_type", "")
    if event_type == "alert":
        process_suricata_alert(event_data)
    elif event_type == "fileinfo":
        process_fileinfo_event(event_data)
    elif event_type == "ssh":
        process_ssh_event(event_data)
    elif event_type == "http":
        process_http_event(event_data)


def tail_log():
    buffer = []
    last_activity = time.time()
    
    with open(LOG_FILE, "r") as f:
        f.seek(0, os.SEEK_END)
        
        while True:
            current_pos = f.tell()
            line = f.readline()
            
            if line:
                try:
                    event_data = json.loads(line)
                    process_event(event_data)
                    last_activity = time.time()
                except json.JSONDecodeError:
                    print(f"Warning: Invalid JSON line: {line.strip()}")
                except Exception as e:
                    print(f"Error processing line: {str(e)}")
            else:
                # Check for log rotation
                try:
                    if os.stat(LOG_FILE).st_ino != os.fstat(f.fileno()).st_ino:
                        print("Log rotated, reopening...")
                        f.close()
                        f = open(LOG_FILE, "r")
                        f.seek(0, os.SEEK_END)
                except FileNotFoundError:
                    pass
                
                time.sleep(0.1)


if __name__ == "__main__":
    print(f"Starting Suricata alert monitor on {LOG_FILE}")
    try:
        tail_log()
    except KeyboardInterrupt:
        print("\nMonitoring stopped")
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        exit(1)
