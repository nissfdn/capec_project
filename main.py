import requests
import zipfile
import io
import pandas as pd
import os

from supabase import create_client
from dotenv import load_dotenv

# .env dosyasındaki çevresel değişkenleri (API anahtarları vb.) sisteme yükler
load_dotenv()

# Supabase bağlantı için gerekli URL ve Key bilgilerini ortam değişkenlerinden alır
supabase_url = os.getenv("SUPABASE_URL")
supabase_key = os.getenv("SUPABASE_KEY")

# Supabase veritabanı istemcisini (client) oluşturur
supabase = create_client(
    supabase_url,
    supabase_key
)

# Harici olarak hazırladığımız parser (ayrıştırma) fonksiyonlarını projeye dahil eder
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


# ============================================================
# 1. MITRE CAPEC VERİSİNİ İNDİRME
# ============================================================

# MITRE güncel CAPEC CSV verisinin sıkıştırılmış (ZIP) indirme adresi
url = "https://capec.mitre.org/data/csv/2000.csv.zip"

print("\n========================================")
print("CAPEC UPDATE TEST")
print("========================================")

print("\n1. MITRE CAPEC verisi indiriliyor...")

# URL üzerinden HTTP GET isteği ile ZIP dosyasını indirir
response = requests.get(url)

# İndirme işleminde bir hata oluştuysa (örn. 404, 500) programı durdurur
response.raise_for_status()

print("MITRE verisi başarıyla indirildi.")


# ============================================================
# 2. ZIP DOSYASINI BELLEKTE AÇMA VE OKUMA
# ============================================================

# İndirilen byte verisini bellekte (RAM) bir dosya gibi açar
with zipfile.ZipFile(
    io.BytesIO(response.content)
) as zip_file:

    print("\nZIP içerisindeki dosyalar:")
    print(zip_file.namelist())

    # ZIP arşivinin içinden ana CSV dosyasını okur
    with zip_file.open("2000.csv") as csv_file:

        # CSV dosyasını Pandas DataFrame yapısına aktarır
        df = pd.read_csv(
            csv_file,
            index_col=False
        )


print("\nCSV başarıyla DataFrame'e aktarıldı.")
print("CAPEC kayıt sayısı:", len(df))


# ============================================================
# 3. KOLON İSİMLERİNİ DÜZENLEME VE STANDARTLAŞTIRMA
# ============================================================

# Kolon adlarındaki olası baş/son boşlukları temizler
df.columns = df.columns.str.strip()

# MITRE CSV başlığındaki tırnak işaretlerini temizler
df.columns = df.columns.str.replace(
    "'",
    "",
    regex=False
)

# Sütun adlarını PostgreSQL veritabanı şemanıza uygun hale getirir
df.columns = [
    "id",
    "name",
    "abstraction",
    "status",
    "description",
    "alternate_terms",
    "likelihood_of_attack",
    "typical_severity",
    "related_attack_patterns",
    "execution_flow",
    "prerequisites",
    "skills_required",
    "resources_required",
    "indicators",
    "consequences",
    "mitigations",
    "example_instances",
    "related_weaknesses",
    "taxonomy_mappings",
    "notes"
]


# ============================================================
# 4. NaN (BOŞ) DEĞERLERİ None (NULL) İLE DEĞİŞTİRME
# ============================================================

# Pandas NaN değerlerini Python / SQL uyumlu None değerlerine dönüştürür
df = df.astype(object).where(
    pd.notna(df),
    None
)

print("Kolonlar hazırlandı.")


# ============================================================
# 5. PARSER (AYRIŞTIRMA) FONKSİYONLARINI ÇALIŞTIRMA
# ============================================================

print("\nParserlar çalıştırılıyor...")

# Her bir ham metin kolonunu ilgili parser fonksiyonundan geçirerek yapılandırır
df["related_weaknesses_parsed"] = df["related_weaknesses"].apply(parse_related_weaknesses)
df["related_attack_patterns_parsed"] = df["related_attack_patterns"].apply(parse_related_attack_patterns)
df["alternate_terms_parsed"] = df["alternate_terms"].apply(parse_alternate_terms)
df["prerequisites_parsed"] = df["prerequisites"].apply(parse_prerequisites)
df["skills_required_parsed"] = df["skills_required"].apply(parse_skills_required)
df["resources_required_parsed"] = df["resources_required"].apply(parse_resources_required)
df["indicators_parsed"] = df["indicators"].apply(parse_indicators)
df["consequences_parsed"] = df["consequences"].apply(parse_consequences)
df["mitigations_parsed"] = df["mitigations"].apply(parse_mitigations)
df["example_instances_parsed"] = df["example_instances"].apply(parse_example_instances)
df["taxonomy_mappings_parsed"] = df["taxonomy_mappings"].apply(parse_taxonomy_mappings)
df["notes_parsed"] = df["notes"].apply(parse_notes)
df["execution_flow_parsed"] = df["execution_flow"].apply(parse_execution_flow)

print("Parserlar başarıyla tamamlandı.")


# ============================================================
# 6. JSON / SUPABASE UYUMLULUĞU İÇİN DÖNÜŞÜM HAZIRLIĞI
# ============================================================

# Supabase JSONB kolonlarına gönderilecek parse edilmiş sütun listesi
parsed_columns = [
    "related_weaknesses_parsed",
    "related_attack_patterns_parsed",
    "alternate_terms_parsed",
    "execution_flow_parsed",
    "prerequisites_parsed",
    "skills_required_parsed",
    "resources_required_parsed",
    "indicators_parsed",
    "consequences_parsed",
    "mitigations_parsed",
    "example_instances_parsed",
    "taxonomy_mappings_parsed",
    "notes_parsed"
]

# Regex sonuçlarındaki Python tuple yapılarını JSON uyumlu listelere dönüştürür
for column in parsed_columns:
    df[column] = df[column].apply(convert_tuples)

print("JSON dönüşümü tamamlandı.")


# ============================================================
# 7. TEST VE KONTROL ÇIKTILARI
# ============================================================

print("\n========================================")
print("TEST SONUCU")
print("========================================")

print("Toplam CAPEC kaydı:", len(df))

print("\nİlk CAPEC ID:")
print(df["id"].iloc[0])

print("\nİlk CAPEC adı:")
print(df["name"].iloc[0])

print("\nİlk related weaknesses:")
print(df["related_weaknesses_parsed"].iloc[0])

print("\nİlk execution flow:")
print(df["execution_flow_parsed"].iloc[0])

print("\n========================================")
print("SUPABASE'E VERİ GÖNDERİLMEDİ.")
print("SADECE TEST YAPILDI.")
print("========================================")