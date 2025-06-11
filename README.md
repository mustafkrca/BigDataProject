# Büyük Veri Projesi: Firewall Log Analizi

## 📊 Proje Hakkında

Bu proje, firewall loglarını makine öğrenmesi teknikleri kullanarak analiz eden kapsamlı bir güvenlik sistemidir. Gerçek zamanlı ağ trafiği analizi, web arayüzü ile takip ve e-posta bildirimleri içerir.

### 🎯 Temel Özellikler

- 🔥 **Gerçek Zamanlı Firewall Monitörü**: Ağ trafiğini canlı takip
- 🤖 **Makine Öğrenmesi**: 14 farklı algoritma ile güvenlik analizi
- 🌐 **Web Arayüzü**: Real-time dashboard ve log görüntüleme
- 📧 **Otomatik Uyarılar**: E-posta bildirimleri ile tehdit tespiti
- 📊 **Kapsamlı Analiz**: 65,000+ firewall log kaydı analizi

## 🗂️ Proje Yapısı

```
├── BigDataModel.ipynb          # Ana model geliştirme ve analiz
├── BigDataAnalysis.ipynb       # Veri analizi ve görselleştirme
├── log2.csv                    # Firewall log veri seti (65,532 kayıt)
├── uygulama/                   # Web uygulaması
│   ├── app.py                  # Flask web sunucusu
│   └── templates/              # HTML şablonları
├── .gitattributes              # Git LFS ayarları
└── README.md                   # Bu dosya
```

## 🔧 Teknik Detaylar

### Makine Öğrenmesi Modelleri

Proje kapsamında 14 farklı makine öğrenmesi algoritması test edilmiştir:

1. **Random Forest** - En iyi performans: %99.7 doğruluk
2. **LightGBM** - %99.7 doğruluk, hızlı işlem
3. **Extra Trees** - %99.7 doğruluk
4. **XGBoost** - %99.7 doğruluk
5. **Decision Tree** - %99.7 doğruluk
6. **Gradient Boosting** - %99.4 doğruluk
7. **k-NN** - %98.9 doğruluk
8. **Gaussian Naive Bayes** - %99.1 doğruluk
9. **SVM (RBF)** - %93.1 doğruluk
10. **Logistic Regression** - %91.1 doğruluk
11. **Linear SVC** - %90.8 doğruluk
12. **AdaBoost** - %88.9 doğruluk
13. **LDA** - %76.6 doğruluk
14. **QDA** - %57.7 doğruluk

### Veri Seti Özellikleri

- **Boyut**: 65,532 kayıt × 12 özellik
- **Hedef Değişken**: action (allow, deny, drop, reset-both)
- **Özellikler**: Port bilgileri, byte sayıları, paket sayıları, zaman bilgileri
- **Dengeleme**: SMOTE tekniği ile sınıf dengelemesi

### Performans Metrikleri

En iyi model (Random Forest):
- **Accuracy**: 99.7%
- **F1-macro**: 84.8%
- **Precision**: 85.9%
- **Recall**: 83.9%
- **Log Loss**: 0.030

## 🚀 Kurulum ve Çalıştırma

### 1. Gereksinimler

```bash
pip install pandas numpy scikit-learn matplotlib seaborn
pip install xgboost lightgbm catboost imbalanced-learn
pip install flask scapy joblib flask-socketio eventlet
```

### 2. Model Eğitimi

```bash
# Jupyter notebook'u açın
jupyter notebook BigDataModel.ipynb

# Veya Python script olarak çalıştırın
python -c "exec(open('BigDataModel.ipynb').read())"
```

### 3. Web Uygulaması

```bash
cd uygulama
python app.py
```

Web arayüzü: `http://localhost:5001`

### 4. Ortam Değişkenleri

`.env` dosyası oluşturun:

```env
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_password
MAIL_TO=alert@domain.com
IFACE=eth0
FLOW_TIMEOUT_SECONDS=1
DASHBOARD_PORT=5001
```

## 📈 Analiz Sonuçları

### Veri Keşfi
- Port dağılımları ve kullanım sıklıkları
- Zaman serisi analizi
- Güvenlik olaylarının kategorik dağılımı

### Model Karşılaştırması
- Ensemble metodları en iyi performansı gösterdi
- Tree-based modeller firewall verisi için ideal
- Deep learning yaklaşımları test edilebilir

### Gerçek Zamanlı Performans
- Milisaniye seviyesinde tahmin süresi
- Düşük bellek kullanımı
- Yüksek throughput desteği

## 🔧 Yapılandırma

### Firewall Kuralları

```bash
# UFW için
ufw allow 5000:5010/tcp

# iptables için
iptables -I INPUT -p tcp --dport 5000:5010 -j ACCEPT

# firewalld için
firewall-cmd --add-port=5000-5010/tcp --permanent
firewall-cmd --reload
```

### Systemd Servisi

```ini
[Unit]
Description=Firewall Sentinel
After=network.target

[Service]
Type=simple
User=sentinel
WorkingDirectory=/opt/firewall-sentinel
ExecStart=/opt/firewall-sentinel/venv/bin/python3 app.py
Restart=always

[Install]
WantedBy=multi-user.target
```

## 📊 Görselleştirmeler

Proje kapsamında oluşturulan grafikler:
- Model performans karşılaştırmaları
- Confusion matrix analizi
- Feature importance çizimleri
- Zaman serisi trendleri
- Port kullanım dağılımları

## 🔒 Güvenlik Özellikleri

### Gerçek Zamanlı Tespit
- Port tarama saldırıları
- Anormal trafik patternleri
- DoS/DDoS saldırı belirtileri
- Suspicious connection attempts

### Uyarı Sistemi
- E-posta bildirimleri
- Web dashboard uyarıları
- Log file kayıtları
- Cooldown mekanizması

