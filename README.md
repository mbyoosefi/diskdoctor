# DiskDoctor

**اسکنر فارنزیک دیسک + موتور ترمیم مبتنی بر شواهد، در یک فایل پایتون بدون هیچ وابستگی.**
**Forensic disk scanner + evidence-based repair engine, in one dependency-free Python file.**

📖 **مستندات کامل / Full documentation: [DOCS.md](DOCS.md)**

---

## فارسی

سه سوال را برای دیسک‌های مشکوک جواب می‌دهد: چه طرح پارتیشن‌بندی‌ای دارد، چه فایل‌سیستمی رویش نشسته، و خرابی چقدر عمیق است — و فقط بعد از آن، جدا، می‌پرسد آیا نوشتن روی آن امن است یا نه. هر ترمیم یا `SAFE_RESTORE` (کپی یک ساختار معتبر موجود روی همان دیسک) است یا `INFERRED_REBUILD` (سنتز از شواهد، با تأیید صریح)؛ بدون اثبات، چیزی نوشته نمی‌شود.

تک‌فایل، Python 3.8+، بدون پکیج بیرونی. ویندوز، لینوکس، یا مستقیم روی فایل ایمیج. پیام‌ها پیش‌فرض فارسی (`--lang en`).

### شروع سریع

```powershell
python diskdoctor.py --self-test          # فقط تست، به دیسک واقعی دست نمی‌زند
python diskdoctor.py --list               # فهرست دیسک‌ها
python diskdoctor.py --auto --all         # فقط خواندن، گزارش کامل
```

برای توضیح کامل هر سوییچ، معماری، Write Gate، جریان کاری پیشنهادی و نکات ایمنی، به **[DOCS.md](DOCS.md)** مراجعه کن — یا:

```
python diskdoctor.py --help-full
```

---

## English

Answers three questions for a disk you're not sure about: what partition scheme, what filesystem, how deep is the damage — and only then, separately, whether it's safe to write anything. Every repair is either `SAFE_RESTORE` (copying a valid structure already on the disk) or `INFERRED_REBUILD` (synthesized from evidence, requires explicit confirmation); nothing is written without proof.

Single file, Python 3.8+, zero dependencies. Windows, Linux, or directly against a raw image file. Messages default to Persian (`--lang en`).

### Quick start

```powershell
python diskdoctor.py --self-test          # tests only, touches no real disk
python diskdoctor.py --list               # enumerate disks
python diskdoctor.py --auto --all         # read-only, full report
```

For full switch reference, architecture, the write gate, recommended workflow, and safety notes, see **[DOCS.md](DOCS.md)** — or:

```
python diskdoctor.py --help-full
```

---

## License / لایسنس

MIT — see [LICENSE](LICENSE).
