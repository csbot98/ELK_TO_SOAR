#!/usr/bin/env python3
import base64
import json
import requests
import aiohttp
import asyncio
import re
import os
import smtplib
import logging
import sys
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from elasticsearch8 import Elasticsearch #9v-el is mükődik, de ha később update során nem menne a script, célszerű újabbb elk modult telepíteni.
from datetime import datetime

# -----------------------------
# ----- Global Settings --
# -----------------------------
###Hibakezelés miatt került be. Fájlba/Konzolra írja az infókat. (Default: True)
debug_mode = False
###Hibakezelés miatt került be, "False" esetén nem kerül be a SOAR-ba az adat. (Default: True)
send_to_soar = True
#Payload kiíratása (Default: False)
payloads_to_console= False
payloads_to_file=False

# Config (ide tedd be külső fájlból is akár)
es_host = "https://1.1.1.1:1111"
es_user = "user"
es_pass = "password"

# Index neve (Opcionálisan cserélhető)
es_index = ".internal.alerts-security.alerts-default-*"

#SOAR info
soar_host = "2.2.2.2"
soar_url= "https://2.2.2.2/#incidents?presetId=-1"
api_key_id = "<APIKEYID>"
api_key_secret = "<APIKEYSECRET>"
org_id = "201"

#Email info
smtp_server = "3.3.3.3"
smtp_port = 25
sender_email = "sender@yourdomain.com" 
to_email="recevier@yourdomain.com"

# Teams URL
webhook_url ="<Teams Webhook URL>"

###Logging
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)  # Alapértelmezett szint, minden üzenetet kiír a konzolra

# Handler a fájlba (csak ERROR és CRITICAL szintű üzenetek)
error_file_handler = logging.FileHandler('elk_script_error.log')
error_file_handler.setLevel(logging.ERROR)  # Csak ERROR és annál súlyosabb üzenetek

# Formatterek beállítása
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
error_file_handler.setFormatter(formatter)

# Handlerek hozzáadása a loggerhez
logger.addHandler(console_handler)
logger.addHandler(error_file_handler)

# -----------------------------
# ----- Functions ----------
# -----------------------------
    
    ##########################
      # Connect to Elastic #
    ##########################
async def connect_to_elasticsearch():
    es_client = Elasticsearch(
        es_host,
        basic_auth=(es_user, es_pass),
        verify_certs=False
    )
    return es_client
    
            #############################
              # Teams Report Part#
            #############################
            
    #############################
      # Send Report via Teams #
    #############################
stats = {
    "successful_incidents": 0,
    "failed_incidents": 0,
    "duplicates": 0,
    "artifacts_created": 0,
    "datatable_rows_added": 0,
}

def reset_stats():
    #Nullázza a statisztikákat a következő időszakhoz.
    global stats
    stats = {
        "successful_incidents": 0,
        "failed_incidents": 0,
        "artifacts_created": 0,
        "datatable_rows_added": 0,
    }

def update_stats(successful=0, failed=0, duplicates=0, artifacts=0, datatable_rows=0):
    #Frissíti a globális statisztikákat.
    global stats
    stats["successful_incidents"] += successful
    stats["failed_incidents"] += failed
    stats["duplicates"] += duplicates
    stats["artifacts_created"] += artifacts
    stats["datatable_rows_added"] += datatable_rows

def create_teams_message():
    #Összeállítja a Teams üzenet payload-ját a jelenlegi statisztikák alapján.
    message_text = (
        f"<strong>Incidens riport:</strong><br>"
        f"• Generált incidensek száma: {stats['successful_incidents']}<br>"
        f"• Hozzáadott artifactok száma: {stats['artifacts_created']}<br>"
        f"• Hozzáadott Data Table sorok száma: {stats['datatable_rows_added']}<br>"
        f"• Sikertelen incidens generálások száma: {stats['failed_incidents']}"
    )
    payload = {
        "text": message_text
    }
    return payload

def reset_stats():
    for key in stats:
        stats[key] = 0

def send_teams_report(webhook_url: str):
    #Elküldi a riportot Teams webhookon keresztül.
    payload = create_teams_message()

    try:
        response = requests.post(webhook_url, json=payload)
        
        if response.status_code == 200:
            if debug_mode:
                logger.debug("Teams riport sikeresen elküldve.")
            reset_stats()  # Nullázzuk a statisztikákat a következő időszakhoz
        else:
            text = response.text
            logger.error(f"Hiba a Teams riport küldésekor: {response.status_code} - {text}")
    
    except Exception as e:
        logger.error(f"Hiba történt a Teams riport küldése közben: {e}")
    
            ##################################
              #End of the Teams Report Part#
            ##################################

    ######################################
      # Load group.id values from file # 
    ######################################    
# Függvény, amely betölti a feldolgozott group.id-ket a fájlból
def load_processed_group_ids(file_path="processed_group_ids.txt"):
    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            return set(line.strip() for line in file)
    return set()

# Függvény, amely appendel egy új group.id-t a fájlhoz
def append_group_id_to_file(group_id, file_path="processed_group_ids.txt"):
    with open(file_path, "a") as file:
        file.write(f"{group_id}\n")

# Függvény, amely menti a frissített group.id-ket a fájlba
def save_processed_group_ids(processed_group_ids, file_path="processed_group_ids.txt"):
    # Ha a fájl létezik, akkor beolvassuk, hogy ne tároljunk duplikált group.id-kat
    existing_group_ids = load_processed_group_ids(file_path)
    
    # Csak az új, még nem létező group.id-ket adjuk hozzá
    new_group_ids = processed_group_ids - existing_group_ids
    
    # Ha van új group.id, akkor hozzáadjuk őket a fájlhoz
    if new_group_ids:
        with open(file_path, "a") as file:
            for group_id in new_group_ids:
                file.write(f"{group_id}\n")
    else:
        if debug_mode:
            logger.debug("Nincs új group.id a mentéshez.")
        
processed_group_ids = load_processed_group_ids()

# Ha nem találunk fájlt, akkor inicializálunk egy üres halmazt
if not processed_group_ids:
    processed_group_ids = set()

    
    ##########################
      # Search doc from ES #
    ##########################
async def search_documents_from_es(es_host, index, query_body, size=100, filename="elk_results.txt"):
    try:
        # Az Elasticsearch URL-je
        url = f"{es_host}/{index}/_search"
        headers = {
            "Content-Type": "application/json"
        }
        auth = aiohttp.BasicAuth(es_user, es_pass)
        query_body["size"] = size
        # Aszinkron HTTP kapcsolat létrehozása
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=query_body, headers=headers, auth=auth, verify_ssl=False) as response:
                # Ha a válasz sikeres (HTTP 200)
                if response.status == 200:
                    data = await response.json()
                    hits = data["hits"]["hits"]

                    # Debug mód engedélyezése esetén
                    if debug_mode:
                        logger.debug(f"DEBUG MODE: ✅ Elasticsearch keresési találatok száma: {len(hits)}")
                        if payloads_to_console:
                            for hit in hits:
                                print(json.dumps(hit["_source"], indent=2, ensure_ascii=False))

                    # Ha szükséges, a találatok fájlba mentése
                    if debug_mode and payloads_to_file:
                        with open(filename, 'w', encoding='utf-8') as file:
                            json.dump(hits, file, indent=2, ensure_ascii=False)
                            print(f"✔️ Az adatokat sikeresen elmentettük a '{filename}' fájlba.")

                    return hits
                else:
                    raise Exception(f"Elasticsearch kérés hiba: {response.status}")
    except Exception as e:
        raise RuntimeError(f"Hiba az Elasticsearch keresésnél: {e}")

    ####################
      # SOAR Connect #
    ####################
def get_soar_headers():
    auth = f"{api_key_id}:{api_key_secret}"
    encoded_auth = base64.b64encode(auth.encode()).decode()
    return {
        "Content-Type": "application/json",
        "Authorization": "Basic " + encoded_auth
    }

    #######################################
      # Check SIEM Rule Name with Query #
    #######################################
def build_query_with_rule_name_check(prefix="TRI_", tags=["tri", "TRI"]):
    return {
        "query": {
            "bool": {
                "should": [  # "should" = vagy-vagy kapcsolat
                    {
                        "wildcard": {
                            "kibana.alert.rule.name": {
                                "value": f"{prefix}*"
                            }
                        }
                    },
                    {
                        "terms": {
                            "kibana.alert.rule.tags": tags  # "tri/TRI" tag keresése
                        }
                    }
                ],
                "minimum_should_match": 1  # Legalább egy feltételnek teljesülnie kell
            }
        },
        "sort": [
            {
                "kibana.alert.original_event.ingested": {
                    "order": "desc"
                }
            }
        ]
    }
        
    #######################################
      # Check group.id #
    #######################################
def classify_hit_by_group_id(hit):
    #Megvizsgálja, hogy van-e group.id:
        #Ha van és egyenlő az adott log alert.id-val, akkor = incidens lesz belőle
        #Ha nincs group.id, akkor is incidens lesz belőle
        #Ha van és nem egyenlő, akkor data table adat lesz belőle és nem incidens!
    doc = hit["_source"]
    alert_id = hit["_id"]
    group_id = doc.get("kibana.alert.group.id")

    if not group_id:
        return "incident"
    elif group_id == alert_id:
        return "incident"
    else:
        return "datatable"


    ###############################
      # Create payload from doc #
    ###############################
def create_payload_from_doc(doc, hit, alert_id=None):
    
    index_name = hit["_index"]  # Lekérjük az index nevét
    alert_id = hit["_id"]  # Lekérjük az alert ID-t
    
    rule_name = doc.get("kibana.alert.rule.name", "Unknown Rule")
    hostname = doc.get("host", {}).get("hostname", "No hostname")
    ip_address = doc.get("host", {}).get("ip", [])[0]
    severity = doc.get("kibana.alert.severity", "Low")  # Alapértelmezett "Low", ha nincs érték
    message = doc.get("kibana.alert.reason", "Unknown")
    alert_url = doc.get("kibana.alert.url", "No Alert URL")
    event_ingested = doc.get("kibana.alert.original_event.ingested", "No time for this event")
    group_id = doc.get("kibana.alert.group.id.", "No Alert Group ID")
    
    # Leírás elkészítése
    description = (
        f"SIEM Rule: {rule_name}\n"
        f"Hostname: {hostname}\n"
        f"Severity: {severity}\n"
        #f"Alert Group ID: {group_id}\n"    #Ez kinda felesleges. A group.id megegyezik az alert.id-val, a fő alert esetén. Mellék alert esetén meg nem kreálódik incidens.
        f"Message: {message}\n"
        f"Event ingested: {event_ingested}\n"
        f"ELK Index name: {index_name}\n"
        f"ELK Alert ID: {alert_id}\n"
        f"ELK Alert URL: {alert_url}"
    )

    severity_map = {
    "low": "Low",
    "medium": "Medium",
    "high": "High"
    }

    #SOAR-ban nincs "Critical" severity, csak "High", így a lekért adat releváns részét módosítjuk.
    severity = "high" if severity == "critical" else severity
    severity_code = severity_map.get(severity.lower(), "Low")

    payload = {
        "name": f"ELK Incident: {rule_name} - {ip_address}",
        "description": description.strip(),
        "severity_code": severity_code,
        "discovered_date": int(datetime.now().timestamp() * 1000)
        #"incident_type_ids": [incident_type_id]
    }

    return payload

    #################################
      # Create artifacts from doc #
    #################################
def extract_artifacts_from_doc(doc):
    artifacts = []
    #Ha definiáljuk a tömb elemeit, hogy pontosan mikre lesz szükség, akkor majd ezt módosítani/élesíteni lehet.
    ##A kinyerendő mezők listája és hozzájuk tartozó metaadatok
    keys_to_check = [
        {"path": ["host", "ip"], "type": "IP Address", "description": "IP cím a SIEM alertből"}, #kiszedi az ipv4/6-ot is egyszer
        {"path": ["host", "hostname"], "type": "String", "description": "Hostname a SIEM alertből"}
        #{"path": ["network", "domain"], "type": "Domain", "description": "Domain név a logból"},
        #{"path": ["file", "name"], "type": "File Name", "description": "Fájlnév a SIEM alertből"},
        #{"path": ["host", "mac"], "type": "MAC Address", "description": "MAC cím a hostból"},
        # Itt bővíthető tovább más mezőkkel
    ]

    for key_info in keys_to_check:
        # Bejárja a megadott "útvonalat" a doc-on belül
        data = doc
        for k in key_info["path"]:
            data = data.get(k, None)
            if data is None:
                break

        # Ha adat van és az lista, akkor vegyük az elsőt
        if data:
            if isinstance(data, list):
                for value in data:
                    artifacts.append({
                        "type": key_info["type"],
                        "value": value,
                        "description": key_info["description"]
                    })
            else:
                artifacts.append({
                    "type": key_info["type"],
                    "value": data,
                    "description": key_info["description"]
                })
                
    return artifacts

    ######################################
      # Search Doc by "group.id" # 
    ######################################    
async def search_documents_by_group_id(es_host, index, group_id, size=100):
    query = {
        "query": {
            "term": {
                "kibana.alert.group.id": group_id
            }
        },
        "size": size
    }
    return await search_documents_from_es(es_host, index, query)
    
    ######################################
      # SOAR Incident description trim#
    ######################################
def extract_alert_id_from_description(description):
    # Feltételezzük, hogy az alert ID az 'ELK Alert ID' kulcsszó után következik
    if "ELK Alert ID:" in description:
        # A split segítségével kinyerjük az alert id-t
        parts = description.split("ELK Alert ID:")
        if len(parts) > 1:
            return parts[1].split("\n")[0].strip()  # Az alert ID a következő sorban
    return None

    #######################################
      # Get existing Alert ID from SOAR #
    #######################################
async def get_soar_alert_ids(alert_id):
    query_payload = {
        "filters": [
            {
                "conditions": [
                    {
                        "field_name": "description",
                        "method": "contains",
                        "value": alert_id
                    }
                ]
            }
        ],
        "start": 0,
        "length": 100  # Például 100 találat lekérése
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"https://{soar_host}/rest/orgs/{org_id}/incidents/query_paged",
                headers=get_soar_headers(),
                data=json.dumps(query_payload),
                ssl=False
            ) as response:
                response.raise_for_status()
                result = await response.json()
                soar_alert_ids = []

                for incident in result.get("data", []):
                    desc = incident.get("description", "")
                    # Kinyerjük az alert_id-t a description-ból
                    soar_alert_id = extract_alert_id_from_description(desc)
                    if soar_alert_id:
                        soar_alert_ids.append(soar_alert_id)  # Csak az alert_id-kat tároljuk
                return soar_alert_ids
    except Exception as e:
        logger.error(f"Hiba a SOAR lekérdezésénél: {e}")
        return []

    ####################################
      # Check if the incident exists #
    ####################################
async def check_if_alert_exists(alert_id):
    soar_alert_ids = await get_soar_alert_ids(alert_id)
    # Megnézzük, hogy bármelyik SOAR description tartalmazza-e az alert_id-t
    for soar_alert_id in soar_alert_ids:
        if alert_id in soar_alert_id:
            return True
    return False

    ##############################################################################
      # Extract Incident ID from the SOAR response after sending the payload #
    ##############################################################################
async def extract_incident_id(response):
    try:
        response_data = await response.json()
        incident_id = response_data.get("id")
        if incident_id:
            return incident_id
        else:
            if debug_mode:
                logger.debug("⚠️ Az incident ID nem található a válaszban.")
            return None
    except Exception as e:
        logger.error(f"❌ Hiba az incident ID kinyerésekor: {e}")
        return None


    #############################
      # Send incident to SOAR #
    #############################
async def send_incident_to_soar(payload):
    if not send_to_soar:
        logger.info("🔕 SOAR küldés letiltva (send_to_soar = False)")
        return {"skipped": True}  # vagy return "disabled", ha az egyszerűbb

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"https://{soar_host}/rest/orgs/{org_id}/incidents",
                headers=get_soar_headers(),
                data=json.dumps(payload),
                ssl=False
            ) as response:
                response_data = await response.json()

                if response.status in [200, 201]:
                    logger.info("✅ Incidens létrehozva.")
                    return response_data
                else:
                    logger.error(f"❌ Sikertelen SOAR incident létrehozás (HTTP {response.status})")
                    return None
    except Exception as e:
        logger.error(f"❌ Hiba a SOAR incident küldésénél: {e}")
        return None


    ##############################################
      #  Send table data to the new incident #
    #############################################
async def add_row_to_soar_datatable(incident_id, doc):
    if not send_to_soar:
        if debug_mode:
            logger.debug("🔕 SOAR Data Table frissítés letiltva (send_to_soar = False)")
        return
        
    hostname = doc.get("host", {}).get("hostname", "N/A")
    ip_list = doc.get("host", {}).get("ip", [])
    ip_address = ip_list[0] if ip_list else "N/A"
    event_name = doc.get("kibana.alert.rule.name", "Unknown Event")
    message = doc.get("message", "No message")
    event_action= doc.get("event.action", "Unknown Action")
    event_outcome= doc.get("event.outcome", "Unknown Outcome")
    alert_url = doc.get("kibana.alert.url", "No Alert URL")
    #Ezt még további mezőkkel kell kiegészíteni.

    # --- Sor adatai a tábla mezői alapján ---
    row_data = {      
        "cells": {
            "event_name": {"value": event_name},
            "hostname": {"value": hostname},
            "source_ip": {"value": ip_address},
            "destination_ip": {"value": "-"},
            "message": {"value": message},
            "event_action": {"value": event_action},
            "event_outcome": {"value": event_outcome},
            "elk_alert_url": {"value": alert_url}
            #További oszlopok kreálása a táblában SOAR UI oldalon!
        }
       }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"https://{soar_host}/rest/orgs/{org_id}/incidents/{incident_id}/table_data/event_information/row_data",
                headers=get_soar_headers(),
                data=json.dumps(row_data),
                ssl=False
            ) as response:
                if response.status in [200, 201]:
                    if debug_mode:
                        logger.debug(f"Sor sikeresen hozzáadva a 'Data Table' táblához (incident ID: {incident_id})")
                else:
                    logger.error(f"Hiba a sor hozzáadásakor. Státusz: {response.status}")
                    logger.error(await response.text())
    except Exception as e:
        logger.error(f"Kivétel történt a Data Table frissítés során: {e}")


    #####################
      # Debug BANNER #
    #####################
def log_debug_banner():
    if debug_mode:
        print("########################")
        print("########################")
        logger.debug("## DEBUG MODE is True ##")
        print("########################")
        print("########################")

    #####################
      # DEBUG Output # Ez jelenleg nincs beépítve jól, később ha lesz hozzá kedvem megoldom, amúgy meg nem SOS.
    #####################
# def handle_debug_output(payload, artifacts, alert_id, doc):
    # if debug_mode:
        # if not send_to_soar:
            # print("🚫 SOAR-ba küldés le van tiltva (send_to_soar = False).")
            # if payloads_to_console:
                # print("🧾 Küldendő payload a SOAR-ba:")
                # print(json.dumps(payload, indent=2, ensure_ascii=False))
            # filename = "soar_payloads.txt"
            # if payloads_to_file: 
                # with open(filename, 'a', encoding='utf-8') as file:
                    # json.dump({
                        # "payload": payload,
                        # "artifacts": artifacts,
                        # "alert_id": alert_id
                    # }, file, indent=2, ensure_ascii=False)
                    # file.write("\n")
                # print(f"✔️ A SOAR payload sikeresen elmentve a '{filename}' fájlba.")
            # print(doc)

    ###############################
      # Processes a single hit # 
    ###############################
group_id_to_incident_id = {}
    
async def process_hit(hit):
    global processed_group_ids, group_id_to_incident_id

    doc = hit["_source"]
    alert_id = hit["_id"]
    group_id = doc.get("kibana.alert.group.id")
    classification = classify_hit_by_group_id(hit)

    soar_alert_ids = await get_soar_alert_ids(alert_id)

    if classification == "incident":
        if group_id and group_id not in processed_group_ids:
            processed_group_ids.add(group_id)

            group_hits = await search_documents_by_group_id(es_host, es_index, group_id)
            payload = create_payload_from_doc(doc, hit)
            artifacts = extract_artifacts_from_doc(doc)
            if artifacts:
                payload["artifacts"] = artifacts

            result = await handle_payload_sending(alert_id, payload)

            if result == 'duplicate':
                # Ha duplikált, csak növeljük a 'duplicates' statot
                update_stats(duplicates=1)
            elif result:
                # Ha sikerült létrehozni az incidentet
                group_id_to_incident_id[group_id] = result
                datatable_row_count = 0
                tasks = []
                for group_hit in group_hits:
                    group_doc = group_hit["_source"]
                    tasks.append(add_row_to_soar_datatable(result, group_doc))
                await asyncio.gather(*tasks)
                datatable_row_count += len(group_hits)
                update_stats(successful=1, artifacts=len(artifacts), datatable_rows=datatable_row_count)
                
            else:
                # Ha nem sikerült létrehozni az incidentet
                update_stats(failed=1)

            append_group_id_to_file(group_id)
        return

    elif classification == "datatable":
        if group_id in group_id_to_incident_id:
            incident_id = group_id_to_incident_id[group_id]
            await add_row_to_soar_datatable(incident_id, doc)
            update_stats(datatable_rows=1)
        else:
            if debug_mode:
                logger.debug(f"group.id ({group_id}) nem található az incident mappingben. Data table hozzáadás kihagyva.")

    ########################################
      # Processes every hit individually #
    ########################################
async def process_hits(hits):
    incident_hits = []
    datatable_hits = []

    for hit in hits:
        classification = classify_hit_by_group_id(hit)
        if classification == "incident":
            incident_hits.append(hit)
        elif classification == "datatable":
            datatable_hits.append(hit)
    # 1. Incident típusú feldolgozás
    await asyncio.gather(*(process_hit(hit) for hit in incident_hits))

    # 2. DataTable sorok feldolgozása
    await asyncio.gather(*(process_hit(hit) for hit in datatable_hits))
    
######################################
      # Send payload/incident to SOAR #
    ######################################
async def handle_payload_sending(alert_id, payload):
    soar_alert_ids = await get_soar_alert_ids(alert_id)

    if alert_id in soar_alert_ids:
        if debug_mode:
            logger.debug(f"⚠️ Incident már létezik SOAR-ban alert_id alapján: '{alert_id}'. Küldés kihagyva.")
        return "duplicate"  # Már létezett

    # Küldés a SOAR-ba csak ha engedélyezett
    response = await send_incident_to_soar(payload)

    if isinstance(response, dict):
        if response.get("skipped"):
            #logger.debug("🟡 SOAR küldés kihagyva (send_to_soar = False)")
            return "disabled"

        incident_id = response.get("id")

        if debug_mode:
            logger.debug("DEBUG: SOAR válasz (incident létrehozva):")
            if payloads_to_console:
                print(json.dumps(response, indent=2))
        return incident_id

    else:
        logger.error(f"❌ Hiba történt az incidens létrehozásakor! Válasz: {response}")
        return None

            
    ########################################
      # Customized HTML body #
    ########################################
def generate_html_body():
    return f"""
    <html>
        <body>
            <h1 style="color: blue;">Reggeli Jelentés</h1>
            <p>Ez az automatikusan küldött <strong>HTML formázott</strong> email!</p>
            <h2>Generált incidensek száma: {stats['successful_incidents']}</h2>
            <p>• Hozzáadott artifactok száma: {stats['artifacts_created']}</p>
            <p>• Hozzáadott Data Table sorok száma: {stats['datatable_rows_added']}</p>
            <p>• Sikertelen incidens generálások száma: {stats['failed_incidents']}</p>
            <a href="{soar_url}">Kattints ide a további részletekhez!</a>
        </body>
    </html>
    """
    
    ########################################
      # Email Notify #
    ########################################
def send_email(subject, body, to_email):
    # E-mail üzenet létrehozása
    message = MIMEMultipart("alternative")
    message["From"] = sender_email
    message["To"] = to_email
    message["Subject"] = subject

    # HTML tartalom hozzáadása a levélhez
    html_body = generate_html_body()
    message.attach(MIMEText(html_body, 'html'))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.sendmail(sender_email, to_email, message.as_string())
            if debug_mode:
                logger.info(f"Email successfully sent to {to_email} with subject: {subject}")
    except Exception as e:
        logger.error(f"Error occurred while sending email: {e}")

# ----------------------------- #
# ----- Main végrehajtás ------ #
# ----------------------------- #
async def main():
    log_debug_banner()

    es = await connect_to_elasticsearch()
    query = build_query_with_rule_name_check()
    hits = await search_documents_from_es(es_host, es_index, query, size=100)

    await process_hits(hits)  # Aszinkron feldolgozás
    ##Ha nem akarjuk időhöz kötni a riport küldést, akkor csak "uncomment" az alábbit.
    # send_email(
            # subject="Reggeli jelentés",
            # body=generate_html_body(),
            # to_email=to_email
        # )
    # send_teams_report(webhook_url)
    
    now = datetime.now()
    # Ha épp 09:00-kor fut, vagy mondjuk 10:00-10:09 között (mivel 10 percenként fut)    
    if now.hour == 10 and now.minute < 10:
        send_email(
            subject="Reggeli jelentés",
            body=generate_html_body(),
            to_email=to_email
        )
        send_teams_report(webhook_url)
        sys.exit()
        
if __name__ == "__main__":
    asyncio.run(main())  # Aszinkron main futtatása
