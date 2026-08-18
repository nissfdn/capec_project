import requests
import zipfile
import io
import pandas as pd

# MITRE CAPEC Comprehensive Dictionary CSV ZIP adresi
url = "https://capec.mitre.org/data/csv/2000.csv.zip"

# ZIP dosyasını indir
response = requests.get(url)

# İndirme başarılı mı kontrol et
response.raise_for_status()

# İndirilen ZIP'i bellekte aç
with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:

    # ZIP içerisindeki dosyaları göster
    print("ZIP içerisindeki dosyalar:")
    print(zip_file.namelist())

#--------||--------
#--------||-------
#-------\||/-----
#--------\/--------

#-------MITRE ye HTTP GET ZIP i aldi RAM de acti.-------------

 # ZIP içerisindeki 2000.csv dosyasını açar
    with zip_file.open("2000.csv") as csv_file:

        # CSV dosyasını Pandas DataFrame'e aktarır
        # İlk sütunun index olarak kullanılmasını engeller.
        df = pd.read_csv(csv_file, index_col=False)


# Kolon isimlerindeki gereksiz boşlukları temizler.
df.columns = df.columns.str.strip()

# "'ID" kolon adını "ID" olarak düzeltir.
df.columns = df.columns.str.replace("'", "", regex=False)

# DataFrame içerisindeki toplam satır sayısını gösterir
print("Number of rows:", len(df))


# DataFrame içerisindeki toplam kolon sayısını gösterir
print("Number of columns:", len(df.columns))


# CSV'deki kolon isimlerini gösterir
print("\nColumns:")
print(df.columns.tolist())


# İlk 5 kaydı gösterir
print("\nFirst 5 records:")
print(df.head())