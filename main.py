import os
import io
import json
import zipfile
import csv
import requests

from capec_parser import (
    parse_related_weaknesses,
    parse_related_attack_patterns,
    parse_alternate_terms,
    parse_prerequisites,
    parse_skills_required,
    parse_resources_required,
    parse_indicators,
    parse_consequences,
    parse_mitigations,
    parse_example_instances,
    parse_taxonomy_mappings,
    parse_notes,
    parse_execution_flow,
    convert_tuples
)

ZIP_URL = "https://capec.mitre.org/data/csv/2000.csv.zip"
JSON_CACHE_FILE = "capec_data.json"

COLUMN_MAPPING = {
    "ID": "id",
    "Name": "name",
    "Abstraction": "abstraction",
    "Status": "status",
    "Description": "description",
    "Alternate Terms": "alternate_terms",
    "Likelihood Of Attack": "likelihood_of_attack",
    "Typical Severity": "typical_severity",
    "Related Attack Patterns": "related_attack_patterns",
    "Execution Flow": "execution_flow",
    "Prerequisites": "prerequisites",
    "Skills Required": "skills_required",
    "Resources Required": "resources_required",
    "Indicators": "indicators",
    "Consequences": "consequences",
    "Mitigations": "mitigations",
    "Example Instances": "example_instances",
    "Related Weaknesses": "related_weaknesses",
    "Taxonomy Mappings": "taxonomy_mappings",
    "Notes": "notes"
}

def clean_val(v):
    if v is None:
        return None
    s = str(v).strip()
    return s if s else None

def load_or_fetch_capec_data(force_refresh=False):
    """
    Returns list of parsed CAPEC dict records.
    If cached JSON exists and force_refresh is False, loads from disk.
    Otherwise downloads zip, parses CSV, caches JSON, and returns data.
    """
    if not force_refresh and os.path.exists(JSON_CACHE_FILE):
        try:
            with open(JSON_CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                print(f"[CACHE] Loaded {len(data)} CAPEC records from {JSON_CACHE_FILE}")
                return data
        except Exception as e:
            print(f"[CACHE] Error loading cache: {e}. Fetching fresh data...")

    print(f"[FETCH] Downloading MITRE CAPEC zip from {ZIP_URL}...")
    resp = requests.get(ZIP_URL, timeout=30)
    resp.raise_for_status()

    capec_records = []

    with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
        filename = "2000.csv" if "2000.csv" in z.namelist() else z.namelist()[0]
        with z.open(filename) as f:
            text_stream = io.TextIOWrapper(f, encoding="utf-8-sig")
            reader = csv.DictReader(text_stream)

            # Strip spaces / quotes from header names
            raw_fieldnames = reader.fieldnames or []
            clean_field_map = {}
            for fn in raw_fieldnames:
                clean_name = fn.strip().replace("'", "")
                mapped_name = COLUMN_MAPPING.get(clean_name, clean_name.lower().replace(" ", "_"))
                clean_field_map[fn] = mapped_name

            for row in reader:
                record = {}
                for raw_col, val in row.items():
                    target_col = clean_field_map.get(raw_col, raw_col)
                    record[target_col] = clean_val(val)

                # Execute Parsers
                raw_rel_weak = record.get("related_weaknesses")
                record["related_weaknesses_parsed"] = convert_tuples(parse_related_weaknesses(raw_rel_weak))

                raw_rel_att = record.get("related_attack_patterns")
                record["related_attack_patterns_parsed"] = convert_tuples(parse_related_attack_patterns(raw_rel_att))

                raw_alt_terms = record.get("alternate_terms")
                record["alternate_terms_parsed"] = convert_tuples(parse_alternate_terms(raw_alt_terms))

                raw_prereqs = record.get("prerequisites")
                record["prerequisites_parsed"] = convert_tuples(parse_prerequisites(raw_prereqs))

                raw_skills = record.get("skills_required")
                record["skills_required_parsed"] = convert_tuples(parse_skills_required(raw_skills))

                raw_resources = record.get("resources_required")
                record["resources_required_parsed"] = convert_tuples(parse_resources_required(raw_resources))

                raw_indicators = record.get("indicators")
                record["indicators_parsed"] = convert_tuples(parse_indicators(raw_indicators))

                raw_consequences = record.get("consequences")
                record["consequences_parsed"] = convert_tuples(parse_consequences(raw_consequences))

                raw_mitigations = record.get("mitigations")
                record["mitigations_parsed"] = convert_tuples(parse_mitigations(raw_mitigations))

                raw_examples = record.get("example_instances")
                record["example_instances_parsed"] = convert_tuples(parse_example_instances(raw_examples))

                raw_taxonomies = record.get("taxonomy_mappings")
                record["taxonomy_mappings_parsed"] = convert_tuples(parse_taxonomy_mappings(raw_taxonomies))

                raw_notes = record.get("notes")
                record["notes_parsed"] = convert_tuples(parse_notes(raw_notes))

                raw_exec_flow = record.get("execution_flow")
                record["execution_flow_parsed"] = convert_tuples(parse_execution_flow(raw_exec_flow))

                capec_records.append(record)

    print(f"[FETCH] Successfully parsed {len(capec_records)} CAPEC records.")

    # Save to local JSON cache
    try:
        with open(JSON_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(capec_records, f, ensure_ascii=False, indent=2)
        print(f"[CACHE] Saved data to {JSON_CACHE_FILE}")
    except Exception as e:
        print(f"[CACHE] Warning: Failed to save cache: {e}")

    return capec_records

if __name__ == "__main__":
    records = load_or_fetch_capec_data(force_refresh=True)
    print(f"Sample Record ID: {records[0].get('id')}, Name: {records[0].get('name')}")