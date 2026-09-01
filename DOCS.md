# DiskDoctor — راهنمای کامل / Full Guide

[English](#english) · [فارسی](#فارسی) · [README](README.md)

---

<div dir="rtl" align="right">

## فارسی

### DiskDoctor چیست؟

DiskDoctor ابزاری برای بررسی دیسک‌ها و ایمیج‌های خامِ مشکوک است. این ابزار پیش از هر اقدامی مشخص می‌کند که دیسک چه ساختاری دارد، فایل‌سیستم آن چیست و نشانه‌های خرابی تا چه حد جدی‌اند. هدف آن بازگرداندن ساختارهای قابل اثبات است، نه حدس زدن یا آزمایش کردن روی داده‌های شما.

این برنامه در یک فایل پایتون اجرا می‌شود، با Python 3.8 و نسخه‌های جدیدتر سازگار است و به هیچ بستهٔ خارجی نیاز ندارد. از ویندوز، لینوکس و فایل‌های ایمیج خام پشتیبانی می‌کند. زبان پیش‌فرض پیام‌ها فارسی است؛ برای انگلیسی از `--lang en` استفاده کنید.

### پیش از شروع

ترمیم دیسک همیشه خطر دارد. DiskDoctor به‌طور پیش‌فرض فقط داده را می‌خواند و هیچ تغییری اعمال نمی‌کند. با این حال، پیش از اجرای هر دستور دارای `--apply`، ابتدا از دیسک ایمیج کامل تهیه کنید:

```powershell
python diskdoctor.py --disk 3 --image-out D:\img\disk3.img
```

اگر دیسک صدای غیرعادی دارد، SMART آن خطا نشان می‌دهد یا خواندن از آن دشوار است، عملیات ترمیم را متوقف کنید. در این وضعیت، اولویت با ایمیج‌گیری و بازیابی داده است، نه تغییر ساختار دیسک.

### این ابزار چه چیزهایی را بررسی می‌کند؟

- طرح پارتیشن‌بندی: GPT، MBR، superfloppy و RAW
- فایل‌سیستم‌ها: NTFS، ReFS، exFAT، FAT12/16/32، ext2/3/4، XFS، Btrfs، Linux swap، LVM2، HFS+، APFS، ISO9660، VMFS و BitLocker
- وضعیت ساختارهای مهم، مانند جدول پارتیشن، بوت‌سکتور و نسخه‌های آینه‌ای
- گستردگی خرابی با گزینهٔ `--triage`

DiskDoctor فقط با پیدا کردن یک امضا نتیجه‌گیری نمی‌کند. برای هر پارتیشنِ احتمالی، چند شاهد مستقل را کنار هم می‌گذارد: اطلاعات جدول پارتیشن، سازگاری فیلدهای بوت‌سکتور، وجود نسخهٔ پشتیبان و امکان اثبات اندازهٔ ولوم از داده‌های همان دیسک. برای دیدن این شواهد از `--explain` استفاده کنید.

### اصل ایمنی در ترمیم

هر عمل ترمیمی در یکی از این سه گروه قرار می‌گیرد:

| وضعیت | مفهوم | نیازمندی |
|---|---|---|
| `SAFE_RESTORE` | یک ساختار معتبر از قبل روی همان دیسک وجود دارد و فقط بازگردانده می‌شود. | `--apply` |
| `INFERRED_REBUILD` | ساختار از مجموعهٔ شواهد بازسازی می‌شود. | `--apply --allow-inferred` |
| `BLOCKED` | شواهد کافی نیست یا انجام کار خطرناک است. | عملیات متوقف می‌شود. |

برای نمونه، بازگرداندن نسخهٔ پشتیبان GPT به هدر اصلی یک `SAFE_RESTORE` است. اما ساختن دوبارهٔ جدول پارتیشن از روی شواهد، `INFERRED_REBUILD` محسوب می‌شود و تأیید صریح بیشتری می‌خواهد.

پیش از نوشتن، DiskDoctor یک Journal ایجاد می‌کند و وضعیت هر تغییر را ثبت می‌کند. اگر فرایند در میانهٔ کار متوقف شود، می‌توانید با `--undo` تغییرات ثبت‌شده را بایت‌به‌بایت بازگردانید.

### روند پیشنهادی

ابتدا برنامه را آزمایش و دیسک‌ها را فهرست کنید:

```powershell
python diskdoctor.py --self-test
python diskdoctor.py --list
```

سپس دیسک موردنظر را فقط‌خواندنی بررسی کنید:

```powershell
python diskdoctor.py --disk 3 --scan --explain --triage --json report.json
```

اگر برنامه یک اقدام ترمیمی پیشنهاد داد، ابتدا آن را بدون `--apply` اجرا کنید تا فقط پیش‌نمایش ببینید:

```powershell
python diskdoctor.py --disk 3 --action gpt-restore-primary
```

فقط پس از تهیهٔ ایمیج و بررسی نتیجه، تغییر را اعمال کنید:

```powershell
python diskdoctor.py --disk 3 --action gpt-restore-primary --apply
```

برای بازگردانی تغییرات ثبت‌شده:

```powershell
python diskdoctor.py --undo diskdoctor_backups\journal_XXXX.json
```

برای بررسی همهٔ دیسک‌ها در حالت فقط‌خواندنی نیز می‌توانید از این دستور استفاده کنید:

```powershell
python diskdoctor.py --auto --all
```

### موارد خارج از محدوده

- DiskDoctor هیچ ساختار ReFS را در سطح سکتور نمی‌نویسد. برای ReFS شواهد را جمع می‌کند و در صورت مناسب بودن، استفاده از `refsutil salvage` را پیشنهاد می‌دهد.
- بازسازی دیسک‌های پویا (LDM) و Storage Spaces پشتیبانی نمی‌شود.
- داده‌ای که واقعاً بازنویسی شده باشد قابل بازگردانی نیست. ترمیم ساختار، دادهٔ پاک‌شده یا بازنویسی‌شده را بازنمی‌گرداند.

### آزمون و کدهای خروج

خودآزمایی با ایمیج‌های مصنوعی انجام می‌شود و به هیچ دیسک واقعی دست نمی‌زند:

```powershell
python diskdoctor.py --self-test
```

| کد | معنی |
|---|---|
| 0 | موفق |
| 1 | خطای عمومی |
| 2 | آرگومان نامعتبر |
| 3 | دسترسی رد شد |
| 4 | هدف پیدا نشد |
| 5 | عملیات لغو شد |
| 6 | خودآزمایی ناموفق بود |
| 7 | نوشتن توسط سازوکار ایمنی رد شد |

### سلب مسئولیت

این ابزار «همان‌گونه که هست» ارائه می‌شود و استفاده از آن کاملاً بر عهدهٔ کاربر است. دستورهای دارای `--apply` یا `--force` ممکن است باعث از دست رفتن داده یا برگشت‌ناپذیر شدن تغییرات شوند. پیش از نوشتن روی هر دیسک، ایمیج یا نسخهٔ پشتیبان کامل تهیه کنید. نویسندگان و مشارکت‌کنندگان پروژه در قبال خسارت، از دست رفتن داده یا اختلال ناشی از استفاده از این ابزار مسئولیتی ندارند.

</div>

---

## English

### What is DiskDoctor?

DiskDoctor examines uncertain disks and raw disk images. Before proposing any action, it identifies the disk layout, filesystem, and apparent severity of damage. Its purpose is to restore structures that can be demonstrated to be valid—not to guess or experiment on your data.

It is a single Python file, works with Python 3.8+, and has no third-party dependencies. It runs on Windows, Linux, and raw image files. Persian is the default interface language; use `--lang en` for English.

### Before you start

Disk repair is inherently risky. DiskDoctor is read-only by default, but before using any command with `--apply`, create a full image of the disk:

```powershell
python diskdoctor.py --disk 3 --image-out D:\img\disk3.img
```

If the disk makes unusual noises, reports SMART failures, or is difficult to read, stop repair work. Image and recover the data first; do not alter the disk structure.

### What it checks

- Partition layouts: GPT, MBR, superfloppy, and RAW
- Filesystems: NTFS, ReFS, exFAT, FAT12/16/32, ext2/3/4, XFS, Btrfs, Linux swap, LVM2, HFS+, APFS, ISO9660, VMFS, and BitLocker
- Critical structures such as partition tables, boot sectors, and mirrors
- Damage extent through `--triage`

DiskDoctor does not treat a single signature as proof. For each possible partition, it combines independent evidence: partition-table data, internally consistent boot-sector fields, a valid backup copy, and a provable volume length. Use `--explain` to inspect that evidence.

### Repair safety model

Every repair falls into one of three classes:

| Status | Meaning | Requirement |
|---|---|---|
| `SAFE_RESTORE` | A valid structure already exists on the same disk and can be restored. | `--apply` |
| `INFERRED_REBUILD` | A structure is reconstructed from supporting evidence. | `--apply --allow-inferred` |
| `BLOCKED` | Evidence is insufficient or the action is unsafe. | The action stops. |

For example, restoring a valid backup GPT header to the primary location is a `SAFE_RESTORE`. Rebuilding a partition table from evidence is an `INFERRED_REBUILD` and requires an additional, explicit confirmation.

Before writing, DiskDoctor creates a journal and records the state of every change. If the process stops partway through, use `--undo` to revert the recorded changes byte-for-byte.

### Recommended workflow

Run the self-test and list disks first:

```powershell
python diskdoctor.py --self-test
python diskdoctor.py --list
```

Inspect a selected disk in read-only mode:

```powershell
python diskdoctor.py --disk 3 --scan --explain --triage --json report.json
```

Preview a suggested repair without `--apply`:

```powershell
python diskdoctor.py --disk 3 --action gpt-restore-primary
```

After imaging the disk and reviewing the result, apply the repair:

```powershell
python diskdoctor.py --disk 3 --action gpt-restore-primary --apply
```

Undo recorded changes if necessary:

```powershell
python diskdoctor.py --undo diskdoctor_backups\journal_XXXX.json
```

To inspect every disk without writing anything:

```powershell
python diskdoctor.py --auto --all
```

### Out of scope

- DiskDoctor never writes ReFS structures at sector level. It gathers evidence and, where appropriate, suggests `refsutil salvage`.
- Dynamic-disk (LDM) and Storage Spaces reconstruction are not supported.
- Structural repair cannot recover data that has genuinely been overwritten.

### Testing and exit codes

The self-test uses synthetic images and never touches a real disk:

```powershell
python diskdoctor.py --self-test
```

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | general error |
| 2 | bad argument |
| 3 | permission denied |
| 4 | target not found |
| 5 | cancelled |
| 6 | self-test failed |
| 7 | write refused by the safety gate |

### Disclaimer

This tool is provided **as is** and is used entirely at your own risk. Commands using `--apply` or `--force` can cause data loss or make changes irreversible. Create a full disk image or backup before writing to any disk. The project authors and contributors are not liable for damage, data loss, or disruption resulting from use of this tool.

---

## License / مجوز

Released under the [MIT License](LICENSE).
