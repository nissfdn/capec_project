import os
from flask import Flask, render_template, jsonify, request
from main import load_or_fetch_capec_data

app = Flask(__name__)

# JSON içindeki dictionary key'lerini sıralamayı kapatır.
# CAPEC verisinde None ve string key'lerin karşılaştırılmasından
# kaynaklanan serialization hatasını önler.
app.json.sort_keys = False

# Global dataset loaded on app start
CAPEC_DATA = load_or_fetch_capec_data(force_refresh=False)

SEVERITY_ORDER = {"Very High": 5, "High": 4, "Medium": 3, "Low": 2, "Very Low": 1}
LIKELIHOOD_ORDER = {"High": 3, "Medium": 2, "Low": 1}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/stats")
def get_stats():
    total = len(CAPEC_DATA)

    severity_counts = {}
    likelihood_counts = {}
    abstraction_counts = {}
    status_counts = {}

    cwe_count = 0
    execution_flow_count = 0

    for item in CAPEC_DATA:
        sev = item.get("typical_severity") or "Unspecified"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        lik = item.get("likelihood_of_attack") or "Unspecified"
        likelihood_counts[lik] = likelihood_counts.get(lik, 0) + 1

        abs_type = item.get("abstraction") or "Unspecified"
        abstraction_counts[abs_type] = abstraction_counts.get(abs_type, 0) + 1

        st = item.get("status") or "Unspecified"
        status_counts[st] = status_counts.get(st, 0) + 1

        if item.get("related_weaknesses_parsed"):
            cwe_count += len(item["related_weaknesses_parsed"])

        if item.get("execution_flow_parsed"):
            execution_flow_count += 1

    return jsonify({
        "total": total,
        "severity": severity_counts,
        "likelihood": likelihood_counts,
        "abstraction": abstraction_counts,
        "status": status_counts,
        "total_cwes_linked": cwe_count,
        "total_with_execution_flow": execution_flow_count
    })

@app.route("/api/capecs")
def get_capecs():
    search = request.args.get("search", "").strip().lower()
    severity = request.args.get("severity", "").strip()
    likelihood = request.args.get("likelihood", "").strip()
    abstraction = request.args.get("abstraction", "").strip()
    status = request.args.get("status", "").strip()

    sort_by = request.args.get("sort_by", "id").strip()
    sort_dir = request.args.get("sort_dir", "asc").strip()

    try:
        page = int(request.args.get("page", 1))
        limit = int(request.args.get("limit", 25))
    except ValueError:
        page = 1
        limit = 25

    filtered = []

    for item in CAPEC_DATA:
        # Severity Filter
        if severity and (item.get("typical_severity") or "") != severity:
            continue

        # Likelihood Filter
        if likelihood and (item.get("likelihood_of_attack") or "") != likelihood:
            continue

        # Abstraction Filter
        if abstraction and (item.get("abstraction") or "") != abstraction:
            continue

        # Status Filter
        if status and (item.get("status") or "") != status:
            continue

        # Search Query Matching
        if search:
            item_id = str(item.get("id") or "")
            item_name = str(item.get("name") or "").lower()
            item_desc = str(item.get("description") or "").lower()
            cwes = " ".join([str(c) for c in item.get("related_weaknesses_parsed", [])]).lower()
            capecs = " ".join([str(ca[1]) for ca in item.get("related_attack_patterns_parsed", []) if len(ca) > 1]).lower()

            match_id = f"capec-{item_id}" in search or item_id == search or search in item_id
            match_name = search in item_name
            match_desc = search in item_desc
            match_cwe = search in cwes or f"cwe-{search}" in cwes or f"cwe-{search.replace('cwe-', '')}" in cwes
            match_capec = search in capecs

            if not (match_id or match_name or match_desc or match_cwe or match_capec):
                continue

        filtered.append(item)

    # Sorting
    reverse = (sort_dir == "desc")
    if sort_by == "id":
        def sort_key(x):
            try:
                return int(x.get("id") or 0)
            except (ValueError, TypeError):
                return 0
        filtered.sort(key=sort_key, reverse=reverse)
    elif sort_by == "name":
        filtered.sort(key=lambda x: str(x.get("name") or "").lower(), reverse=reverse)
    elif sort_by == "severity":
        filtered.sort(key=lambda x: SEVERITY_ORDER.get(x.get("typical_severity"), 0), reverse=reverse)
    elif sort_by == "likelihood":
        filtered.sort(key=lambda x: LIKELIHOOD_ORDER.get(x.get("likelihood_of_attack"), 0), reverse=reverse)

    total_records = len(filtered)
    start_idx = (page - 1) * limit
    end_idx = start_idx + limit
    paginated_items = filtered[start_idx:end_idx]

    return jsonify({
        "total": total_records,
        "page": page,
        "limit": limit,
        "total_pages": (total_records + limit - 1) // limit if limit > 0 else 1,
        "items": paginated_items
    })

@app.route("/api/capec/<item_id>")
def get_capec_detail(item_id):
    item_id_str = str(item_id).replace("CAPEC-", "").replace("capec-", "").strip()
    for item in CAPEC_DATA:
        if str(item.get("id")) == item_id_str:
            return jsonify(item)
    return jsonify({"error": "CAPEC record not found"}), 404

@app.route("/api/refresh", methods=["POST"])
def refresh_data():
    global CAPEC_DATA
    try:
        CAPEC_DATA = load_or_fetch_capec_data(force_refresh=True)
        return jsonify({"success": True, "count": len(CAPEC_DATA)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == "__main__":
    print("Starting CAPEC Explorer Web Server on http://127.0.0.1:5050 ...")
    app.run(host="127.0.0.1", port=5050, debug=False)