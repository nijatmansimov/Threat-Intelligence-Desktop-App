# 📘 Threat Intelligence Checker

`Threat Intelligence Checker` — şübhəli **IP** və **faylları** analiz etmək üçün hazırlanmış **PyQt5 əsaslı təhlükəsizlik aləti**dir.
Bu tətbiq müxtəlif Threat Intelligence (TI) platformalarından istifadə edərək nəticələri vahid interfeys üzərində göstərir.

---

## ✨ Xüsusiyyətlər

* 🔍 **IP ünvanlarının yoxlanması** (məs: AbuseIPDB inteqrasiyası)
* 🗂 **Fayl analizləri** (hash çıxarma və təhlükə skan edilməsi)
* 🎨 **Modern PyQt5 GUI** (işlək tab sistemi, hover effektləri, terminal-stil nəticələr paneli)
* 📊 **Nəticələrin saxlanılması** (JSON və ya fayl formasında ixrac)
* 🖥 **Dual Mod** (GUI və CLI istifadəsi üçün uyğunlaşdırıla bilər)

---

## ⚙️ Quraşdırma

### 1️⃣ Repository-ni klonla

```bash
git clone https://github.com/yourusername/threat-intelligence-checker.git
cd threat-intelligence-checker
```

### 2️⃣ Virtual mühit yarat (opsional, amma tövsiyə olunur)

```bash
python3 -m venv venv
source venv/bin/activate   # Linux/macOS
venv\Scripts\activate      # Windows
```

### 3️⃣ Asılılıqları quraşdır

```bash
pip install -r requirements.txt
```

`requirements.txt` nümunəsi:

```txt
PyQt5
requests
reportlab
python-docx
```

---

## 🚀 İstifadə

### GUI rejimində işə salmaq

```bash
python3 checker.py
```

➡️ PyQt5 əsaslı interfeys açılacaq. Burada:

* **IP Scan** tab-ında IP daxil edib `Scan` basaraq nəticələri görə bilərsiniz.
* **File Scan** tab-ında fayl seçib analiz edə bilərsiniz.

### CLI rejimində işə salmaq (opsional)

Əgər GUI işlətmək istəmirsinizsə, CLI dəstəyi əlavə edilə bilər:

```bash
python3 checker.py --ip 8.8.8.8
python3 checker.py --file sample.exe
```

---

## 🛠 Struktur

```
threat-intelligence-checker/
│── checker.py           # Əsas tətbiq (PyQt5 GUI + TI inteqrasiyası)
│── requirements.txt     # Python asılılıqları
│── README.md            # Bu sənəd
```

---

## 🤝 Töfhə Vermək

1. Repo-nu fork edin
2. Yeni branch yaradın: `git checkout -b feature/my-feature`
3. Dəyişikliklərinizi edin və commit edin
4. Branch-i push edin: `git push origin feature/my-feature`
5. Pull Request açın
