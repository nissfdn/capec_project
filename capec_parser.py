import re
import pandas as pd


# ============================================================
# 1. İLİŞKİLİ ZAYIFLIKLAR (RELATED WEAKNESSES) AYIRICI
# ============================================================
def parse_related_weaknesses(value):
    """Zayıflık alanındaki :: ile ayrılmış CWE ID'lerini yakalar."""
    if value is None:
        return []

    # İki çift iki nokta üst üste (::) arasındaki sayısal değerleri bulur
    return re.findall(
        r"(?<=::)\d+(?=::)",
        value
    )


# ============================================================
# 2. İLİŞKİLİ SALDIRI ÖRNEKLERİ (RELATED ATTACK PATTERNS) AYIRICI
# ============================================================
def parse_related_attack_patterns(value):
    """Saldırı desenleri arasındaki doğa türünü ve CAPEC ID'yi ayırır."""
    if value is None:
        return []

    return re.findall(
        r"NATURE:([^:]+):CAPEC ID:(\d+)",
        value
    )


# ============================================================
# 3. ALTERNATİF TERİMLER (ALTERNATE TERMS) AYIRICI
# ============================================================
def parse_alternate_terms(value):
    """Alternatif terim tanım bloklarındaki metinleri ayıklar."""
    if pd.isna(value):
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
    if value is None:
        return []

    return re.findall(
        r"(?<=::)(.*?)(?=::)",
        value
    )


# ============================================================
# 5. GEREKLİ YETENEKLER (SKILLS REQUIRED) AYIRICI
# ============================================================
def parse_skills_required(value):
    """Saldırganın sahip olması gereken beceri ve seviye bilgilerini listeler."""
    if value is None:
        return []

    matches = re.findall(
        r"SKILL:(.*?):LEVEL:(.*?):",
        value
    )

    # Bulunan verileri sözlük (dictionary) listesine dönüştürür
    return [
        {
            "skill": skill,
            "level": level
        }
        for skill, level in matches
    ]


# ============================================================
# 6. GEREKLİ KAYNAKLAR (RESOURCES REQUIRED) AYIRICI
# ============================================================
def parse_resources_required(value):
    """Saldırı için gereken araç veya kaynak tanımlarını ayırır."""
    if value is None:
        return []

    return re.findall(
        r"(?<=::)(.*?)(?=::)",
        value
    )


# ============================================================
# 7. GÖSTERGELER (INDICATORS) AYIRICI
# ============================================================
def parse_indicators(value):
    """Saldırı belirtilerini/göstergelerini yakalar."""
    if value is None:
        return []

    return re.findall(
        r"(?<=::)(.*?)(?=::)",
        value
    )


# ============================================================
# 8. SONUÇLAR VE ETKİLER (CONSEQUENCES) AYIRICI
# ============================================================
def parse_consequences(value):
    """Saldırı sonucundaki kapsam (scope) ve teknik etki (technical impact) alanlarını ayırır."""
    if value is None:
        return {
            "scope": [],
            "technical_impact": []
        }

    scopes = re.findall(
        r"SCOPE:(.*?)(?=:SCOPE|:TECHNICAL IMPACT|::)",
        value
    )

    technical_impacts = re.findall(
        r"TECHNICAL IMPACT:(.*?):",
        value
    )

    return {
        "scope": scopes,
        "technical_impact": technical_impacts
    }


# ============================================================
# 9. AZALTMA / ÖNLEME YOLLARI (MITIGATIONS) AYIRICI
# ============================================================
def parse_mitigations(value):
    """Güvenlik önlemleri ve azaltma stratejilerini ayırır."""
    if value is None:
        return []

    return re.findall(
        r"(?<=::)(.*?)(?=::)",
        value
    )


# ============================================================
# 10. ÖRNEK VAKALAR (EXAMPLE INSTANCES) AYIRICI
# ============================================================
def parse_example_instances(value):
    """Gerçek dünya örneklerini barındıran metin bloklarını yakalar."""
    if value is None:
        return []

    return re.findall(
        r"(?<=::)(.*?)(?=::)",
        value
    )


# ============================================================
# 11. TAKSONOMİ EŞLEŞMELERİ (TAXONOMY MAPPINGS) AYIRICI
# ============================================================
def parse_taxonomy_mappings(value):
    """Farklı sınıflandırma sistemleriyle (örn. CWE, ATT&CK) eşleşme bilgilerini düzenler."""
    if pd.isna(value):
        return []

    matches = re.findall(
        r"TAXONOMY NAME:(.*?):ENTRY ID:(.*?):ENTRY NAME:(.*?)(?:::|$)",
        str(value)
    )

    return [
        {
            "taxonomy_name": taxonomy_name,
            "entry_id": entry_id,
            "entry_name": entry_name
        }
        for taxonomy_name, entry_id, entry_name in matches
    ]


# ============================================================
# 12. NOTLAR (NOTES) AYIRICI
# ============================================================
def parse_notes(value):
    """Kayıt içerisindeki notların türünü ve açıklamasını ayrıştırır."""
    if value is None:
        return []

    matches = re.findall(
        r"TYPE:(.*?):NOTE:(.*?)(?::::|$)",
        value
    )

    return [
        {
            "type": note_type,
            "note": note
        }
        for note_type, note in matches
    ]


# ============================================================
# 13. SALDIRI AKIŞI (EXECUTION FLOW) AYIRICI
# ============================================================
def parse_execution_flow(value):
    """Saldırının adım adım ilerleyişini, evrelerini ve kullanılan teknikleri parçalar."""
    if value is None:
        return []

    step_blocks = re.findall(
        r"::STEP:(\d+):PHASE:(.*?):DESCRIPTION:(.*?)(?=::STEP:|$)",
        value
    )

    results = []

    for step, phase, content in step_blocks:
        description_match = re.match(
            r"(.*?)(?=:TECHNIQUE:|$)",
            content
        )

        description = (
            description_match.group(1)
            if description_match
            else ""
        )

        techniques = re.findall(
            r":TECHNIQUE:(.*?)(?=:TECHNIQUE:|::|$)",
            content
        )

        techniques = [
            technique.rstrip(":")
            for technique in techniques
        ]

        results.append(
            {
                "step": step,
                "phase": phase,
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