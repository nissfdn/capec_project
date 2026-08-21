import re

# ============================================================
# 1. İLİŞKİLİ ZAYIFLIKLAR (RELATED WEAKNESSES) AYIRICI
# ============================================================
def parse_related_weaknesses(value):
    """Zayıflık alanındaki :: ile ayrılmış CWE ID'lerini yakalar."""
    if not value:
        return []

    return re.findall(
        r"(?<=::)\d+(?=::)",
        str(value)
    )


# ============================================================
# 2. İLİŞKİLİ SALDIRI ÖRNEKLERİ (RELATED ATTACK PATTERNS) AYIRICI
# ============================================================
def parse_related_attack_patterns(value):
    """Saldırı desenleri arasındaki doğa türünü ve CAPEC ID'yi ayırır."""
    if not value:
        return []

    return re.findall(
        r"NATURE:([^:]+):CAPEC ID:(\d+)",
        str(value)
    )


# ============================================================
# 3. ALTERNATİF TERİMLER (ALTERNATE TERMS) AYIRICI
# ============================================================
def parse_alternate_terms(value):
    """Alternatif terim tanım bloklarındaki metinleri ayıklar."""
    if not value:
        return []

    return re.findall(
        r"TERM:(.*?):DESCRIPTION",
        str(value)
    )


# ============================================================
# 4. ÖN KOŞULLAR (PREREQUISITES) AYIRICI
# ============================================================
def parse_prerequisites(value):
    """Saldırı için gerekli ön koşul ifadelerini yakalar."""
    if not value:
        return []

    matches = re.findall(r"(?<=::)(.*?)(?=::|$)", str(value))
    return [m.strip() for m in matches if m.strip() and m.strip() != "::"]


# ============================================================
# 5. GEREKLİ YETENEKLER (SKILLS REQUIRED) AYIRICI
# ============================================================
def parse_skills_required(value):
    """Saldırganın sahip olması gereken beceri ve seviye bilgilerini listeler."""
    if not value:
        return []

    matches = re.findall(
        r"SKILL:(.*?):LEVEL:(.*?):",
        str(value)
    )

    return [
        {
            "skill": skill.strip(),
            "level": level.strip()
        }
        for skill, level in matches
    ]


# ============================================================
# 6. GEREKLİ KAYNAKLAR (RESOURCES REQUIRED) AYIRICI
# ============================================================
def parse_resources_required(value):
    """Saldırı için gereken araç veya kaynak tanımlarını ayırır."""
    if not value:
        return []

    matches = re.findall(r"(?<=::)(.*?)(?=::|$)", str(value))
    return [m.strip() for m in matches if m.strip() and m.strip() != "::"]


# ============================================================
# 7. GÖSTERGELER (INDICATORS) AYIRICI
# ============================================================
def parse_indicators(value):
    """Saldırı belirtilerini/göstergelerini yakalar."""
    if not value:
        return []

    matches = re.findall(r"(?<=::)(.*?)(?=::|$)", str(value))
    return [m.strip() for m in matches if m.strip() and m.strip() != "::"]


# ============================================================
# 8. SONUÇLAR VE ETKİLER (CONSEQUENCES) AYIRICI
# ============================================================
def parse_consequences(value):
    """Saldırı sonucundaki kapsam (scope) ve teknik etki (technical impact) alanlarını ayırır."""
    if not value:
        return {
            "scope": [],
            "technical_impact": []
        }

    scopes = re.findall(
        r"SCOPE:(.*?)(?=:SCOPE|:TECHNICAL IMPACT|::|$)",
        str(value)
    )

    technical_impacts = re.findall(
        r"TECHNICAL IMPACT:(.*?)(?=:SCOPE|:TECHNICAL IMPACT|::|$)",
        str(value)
    )

    return {
        "scope": [s.strip() for s in scopes if s.strip()],
        "technical_impact": [t.strip() for t in technical_impacts if t.strip()]
    }


# ============================================================
# 9. AZALTMA / ÖNLEME YOLLARI (MITIGATIONS) AYIRICI
# ============================================================
def parse_mitigations(value):
    """Güvenlik önlemleri ve azaltma stratejilerini ayırır."""
    if not value:
        return []

    matches = re.findall(r"(?<=::)(.*?)(?=::|$)", str(value))
    return [m.strip() for m in matches if m.strip() and m.strip() != "::"]


# ============================================================
# 10. ÖRNEK VAKALAR (EXAMPLE INSTANCES) AYIRICI
# ============================================================
def parse_example_instances(value):
    """Gerçek dünya örneklerini barındıran metin bloklarını yakalar."""
    if not value:
        return []

    matches = re.findall(r"(?<=::)(.*?)(?=::|$)", str(value))
    return [m.strip() for m in matches if m.strip() and m.strip() != "::"]


# ============================================================
# 11. TAKSONOMİ EŞLEŞMELERİ (TAXONOMY MAPPINGS) AYIRICI
# ============================================================
def parse_taxonomy_mappings(value):
    """Farklı sınıflandırma sistemleriyle (örn. CWE, ATT&CK) eşleşme bilgilerini düzenler."""
    if not value:
        return []

    matches = re.findall(
        r"TAXONOMY NAME:(.*?):ENTRY ID:(.*?):ENTRY NAME:(.*?)(?:::|$)",
        str(value)
    )

    return [
        {
            "taxonomy_name": taxonomy_name.strip(),
            "entry_id": entry_id.strip(),
            "entry_name": entry_name.strip()
        }
        for taxonomy_name, entry_id, entry_name in matches
    ]


# ============================================================
# 12. NOTLAR (NOTES) AYIRICI
# ============================================================
def parse_notes(value):
    """Kayıt içerisindeki notların türünü ve açıklamasını ayrıştırır."""
    if not value:
        return []

    matches = re.findall(
        r"TYPE:(.*?):NOTE:(.*?)(?::::|$)",
        str(value)
    )

    return [
        {
            "type": note_type.strip(),
            "note": note.strip()
        }
        for note_type, note in matches
    ]


# ============================================================
# 13. SALDIRI AKIŞI (EXECUTION FLOW) AYIRICI
# ============================================================
def parse_execution_flow(value):
    """Saldırının adım adım ilerleyişini, evrelerini ve kullanılan teknikleri parçalar."""
    if not value:
        return []

    step_blocks = re.findall(
        r"::STEP:(\d+):PHASE:(.*?):DESCRIPTION:(.*?)(?=::STEP:|$)",
        str(value)
    )

    results = []

    for step, phase, content in step_blocks:
        description_match = re.match(
            r"(.*?)(?=:TECHNIQUE:|$)",
            content
        )

        description = (
            description_match.group(1).strip()
            if description_match
            else ""
        )

        techniques = re.findall(
            r":TECHNIQUE:(.*?)(?=:TECHNIQUE:|::|$)",
            content
        )

        techniques = [
            technique.rstrip(":").strip()
            for technique in techniques
            if technique.strip()
        ]

        results.append(
            {
                "step": step.strip(),
                "phase": phase.strip(),
                "description": description,
                "techniques": techniques
            }
        )

    return results


# ============================================================
# 14. TUPLE → JSON UYUMLU DÖNÜŞÜM YARDIMCISI
# ============================================================
def convert_tuples(value):
    """Regex kaynaklı Python tuple yapılarını Supabase/JSON uyumlu listelere recursive dönüştürür."""
    if isinstance(value, tuple):
        return list(value)

    if isinstance(value, list):
        return [
            convert_tuples(item)
            for item in value
        ]

    if isinstance(value, dict):
        return {
            key: convert_tuples(val)
            for key, val in value.items()
        }

    return value