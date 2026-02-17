# AltaySec Cloud Security Scanner

<div align="center">


[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![AWS](https://img.shields.io/badge/AWS-Read%20Only-orange.svg)](https://aws.amazon.com/)
[![Used in AltaySec Atölye](https://img.shields.io/badge/Used%20in-AltaySec%20Atolye-b91c1c?style=flat-square)](https://atolye.altaysec.com.tr)


</div>

> 🤝 Bu proje, **AltaySec** topluluğu / Atölye çalışmaları kapsamında geliştirildi.


AWS bulut ortamlarında güvenlik yapılandırma hatalarını (misconfiguration) tespit eden read-only güvenlik tarayıcısı.

## Özellikler

- **Tam Read-Only**: AWS ortamına sadece okuma erişimi (list/describe/get)
- **Kapsamlı Kontroller**: S3, IAM, EC2 Security Groups, RDS, ELB/ALB
- **Risk Skorlama**: 0-100 arası güvenlik skoru
- **Türkçe Çıktı**: Tüm raporlar ve mesajlar Türkçe
- **Modern UI**: Rich kütüphanesi ile renkli, yapılandırılmış terminal çıktısı
- **Hata Toleransı**: AccessDenied durumlarında çökmez, kısmi tarama yapar
- **Mock Mode**: AWS'e bağlanmadan demo tarama çalıştırma

## Desteklenen Kontroller

### S3 Bucket Güvenliği
- PublicAccessBlock konfigürasyonu
- Bucket policy public principal kontrolü
- ACL public erişim
- Default encryption durumu
- Versioning aktif mi

### IAM Güvenliği
- AdministratorAccess atamaları
- Wildcard action/resource kullanımı
- Eski access key (>90 gün)
- MFA durumu

### Ağ Güvenliği
- EC2 Security Group 0.0.0.0/0 kontrolleri
- Yaygın portlara (SSH, RDP, DB) genel erişim
- Web servisleri (80/443) değerlendirmesi

### RDS Güvenliği
- PubliclyAccessible ayarı

### Load Balancer Güvenliği
- Internet-facing ELB/ALB tespiti
- İlişkili security group analizleri

## Kurulum

```bash
# GitHub'dan klonla
https://github.com/koray-yolcu-sec/altay_cloud_scanner.git
cd altay-cloud-scanner

# Sanal ortam oluştur (önerilir)
python -m venv venv
source venv/bin/activate  # Linux/Mac
# veya
venv\Scripts\activate  # Windows

# Yükle
pip install -e .
```

## Gereksinimler

- Python 3.9 veya üzeri
- AWS CLI yapılandırılmış credential'lar veya environment variables
- AWS hesabı için read-only IAM izinleri

## IAM İzinleri

Bu tarayıcı sadece read-only işlem yapar. Gerekli minimum IAM policy `docs/iam_readonly_policy.json` dosyasında bulunabilir.

## Kullanım

### Temel Tarama

```bash
# Default profile ile tek bölge taraması
altay-cloud scan --profile default --region eu-north-1

# Tüm bölgeleri tara
altay-cloud scan --profile default --regions all

# Beklenen AWS account ID ile doğrulama
altay-cloud scan --profile default --region eu-north-1 --expected-account 123456789012
```

### Çıktı Seçenekleri

```bash
# JSON çıktısı kaydet
altay-cloud scan --profile default --region eu-north-1 --output json --out results.json
```

### Mock Mode (Demo)

```bash
# AWS'e bağlanmadan demo tarama
altay-cloud scan --mock
```

## CLI Parametreleri

| Parametre | Açıklama |
|-----------|----------|
| `--profile` | AWS profile adı |
| `--region` | Tek bölge (örn: eu-north-1) |
| `--regions` | Bölge listesi veya `all` |
| `--expected-account` | Beklenen AWS Account ID (12 haneli) |
| `--output` | Çıktı formatı (terminal/json) |
| `--out` | Çıktı dosyası (json için) |
| `--mock` | Demo modu |
| `--verbose` | Detaylı çıktı |

## Bulgu Formatı

```json
{
  "id": "AWS-S3-PUBLIC-001",
  "title": "S3 Bucket PublicAccessBlock Kapalı",
  "severity": "high",
  "confidence": "high",
  "service": "s3",
  "resource": {
    "arn": "arn:aws:s3:::example-bucket",
    "name": "example-bucket",
    "region": "eu-north-1"
  },
  "evidence": ["PublicAccessBlock konfigürasyonu yok veya devre dışı"],
  "risk": "Bucket içerikleri internete açık olabilir",
  "recommendation": [
    "PublicAccessBlock aktif et",
    "Bucket policy'yi gözden geçir"
  ],
  "score_impact": -15,
  "tags": ["s3", "public-access", "storage"]
}
```

## Risk Skoru

- **100**: En iyi, güvenli yapılandırma
- **70-99**: İyi, bazı iyileştirmeler gerekli
- **40-69**: Orta risk, kritik bulgular var
- **0-39**: Yüksek risk, acil aksiyon gerekli
- **N/A**: Kısmi tarama, bazı check'ler başarısız

## Güvenlik Notları

1. **Read-Only**: Bu araç AWS kaynaklarını asla değiştirmez
2. **Credential Güvenliği**: Credentials, secrets ve token'lar asla loglanmaz
3. **Hata Yönetimi**: AccessDenied durumunda tarama durmaz, sadece ilgili check atlanır
4. **Throttling**: AWS API limitlerini aşmamak için exponential backoff kullanılır

## Sorun Bildirme

Sorunları GitHub Issues üzerinden bildirebilirsiniz.

## Lisans

MIT License

## Yazar

Koray Yolcu (kkyolcu@gmail.com)

## Teşekkürler

- AWS ve bulut güvenliği topluluğuna
- Rich kütüphanesi geliştiricilerine
