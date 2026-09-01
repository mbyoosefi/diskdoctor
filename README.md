# DiskDoctor

> **اسکن و ترمیم ایمن دیسک، بر پایهٔ شواهد — در یک فایل پایتون و بدون وابستگی خارجی.**
> **Evidence-based disk scanning and safe repair — one dependency-free Python file.**

[English](#english) · [فارسی](#فارسی) · [مستندات کامل / Full documentation](DOCS.md)

---

## فارسی

DiskDoctor برای بررسی دیسک‌های مشکوک طراحی شده است. ابتدا مشخص می‌کند دیسک چه طرح پارتیشن‌بندی و چه فایل‌سیستمی دارد و میزان خرابی آن چقدر است؛ سپس، به‌صورت مستقل، ارزیابی می‌کند که آیا نوشتن روی دیسک ایمن است یا خیر.

اصل بنیادین ابزار ساده است: **بدون شواهد کافی، هیچ چیزی نوشته نمی‌شود.**

- `SAFE_RESTORE` — بازگردانی یک ساختار معتبر که از قبل روی همان دیسک وجود دارد.
- `INFERRED_REBUILD` — بازسازی بر اساس شواهد؛ فقط با تأیید صریح کاربر انجام می‌شود.

### ویژگی‌ها

- یک فایل، سازگار با Python 3.8 و بالاتر، بدون نیاز به پکیج خارجی
- قابل اجرا در ویندوز، لینوکس و روی فایل ایمیج خام
- حالت پیش‌فرض فقط‌خواندنی؛ هیچ تغییری بدون `--apply` اعمال نمی‌شود
- پیام‌ها به‌صورت پیش‌فرض فارسی هستند؛ برای انگلیسی از `--lang en` استفاده کنید

### شروع سریع

```powershell
python diskdoctor.py --self-test  # اجرای تست‌ها؛ بدون دست‌زدن به دیسک واقعی
python diskdoctor.py --list       # نمایش فهرست دیسک‌ها
python diskdoctor.py --auto --all # اسکن فقط‌خواندنی و تولید گزارش کامل
```

برای مشاهدهٔ همهٔ گزینه‌ها:

```powershell
python diskdoctor.py --help-full
```

جزئیات معماری، سازوکار محافظت از نوشتن، گردش‌کار پیشنهادی و نکات ایمنی در [مستندات کامل](DOCS.md) آمده است.

### سلب مسئولیت

این ابزار «همان‌گونه که هست» ارائه می‌شود و استفاده از آن کاملاً بر عهدهٔ کاربر است. هرگونه عملیات ترمیمی، به‌ویژه اجرای دستورهای دارای `--apply`، می‌تواند به از دست رفتن داده یا غیرقابل‌بازگشت شدن تغییرات منجر شود. پیش از هرگونه نوشتن روی دیسک، از آن ایمیج یا نسخهٔ پشتیبان کامل تهیه کنید. نویسندگان و مشارکت‌کنندگان پروژه مسئول هیچ‌گونه خسارت، از دست رفتن داده یا اختلال ناشی از استفاده از این ابزار نیستند.

---

## English

DiskDoctor investigates disks whose state is uncertain. It first identifies the partition layout, filesystem, and depth of damage; only then does it independently assess whether writing to the disk is safe.

Its core rule is simple: **nothing is written without sufficient evidence.**

- `SAFE_RESTORE` — restores a valid structure that already exists on the same disk.
- `INFERRED_REBUILD` — reconstructs a structure from evidence and requires explicit user confirmation.

### Highlights

- One file, Python 3.8+, with no third-party dependencies
- Runs on Windows, Linux, and raw disk-image files
- Read-only by default; no change is made without `--apply`
- Persian is the default interface language; use `--lang en` for English

### Quick start

```powershell
python diskdoctor.py --self-test  # run tests only; never touches a real disk
python diskdoctor.py --list       # list available disks
python diskdoctor.py --auto --all # read-only scan and complete report
```

For the complete command reference:

```powershell
python diskdoctor.py --help-full
```

See the [full documentation](DOCS.md) for the architecture, write gate, recommended workflow, and safety guidance.

### Disclaimer

This tool is provided **as is** and is used entirely at your own risk. Any repair operation—especially a command using `--apply`—can cause data loss or make changes irreversible. Create a complete disk image or backup before writing to a disk. The project authors and contributors are not liable for any damage, data loss, or disruption resulting from use of this tool.

---

## License / مجوز

Released under the [MIT License](LICENSE).
