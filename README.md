# DiskDoctor

<div dir="rtl" align="right" lang="fa">

## فارسی

**<bdi dir="ltr">DiskDoctor</bdi>** ابزار تک‌فایلی پایتون برای بررسی فارنزیک دیسک و طراحی ترمیم بر پایهٔ شواهد است. برای موقعیت‌هایی ساخته شده که پس از تغییر یا جابه‌جایی دیسک یا دیسک مجازی، پارتیشن یا فایل‌سیستم به‌درستی خوانده نمی‌شود.

> [!WARNING]
> این پروژه فقط اشتراک تجربه و ابزاری برای بررسی اولیه است؛ بازیابی داده یا بی‌خطر بودن هیچ اقدامی را تضمین نمی‌کند. مسئولیت کامل هرگونه خرابی، ازدست‌رفتن داده و نتیجهٔ اجرای دستورها با کاربر است. پیش از هر اقدام، خروجی را بررسی کنید، از دیسک ایمیج بگیرید و فقط وقتی از هدف و نتیجهٔ مورد انتظار مطمئن هستید، اجازهٔ نوشتن بدهید.

### کارکرد ابزار

DiskDoctor ابتدا سه موضوع را بررسی می‌کند:

1. طرح پارتیشن‌بندی دیسک چیست؟
2. روی هر پارتیشن چه فایل‌سیستمی قرار دارد؟
3. آسیب تا چه حد عمیق است و آیا شواهد کافی برای ترمیم وجود دارد؟

تنها پس از این بررسی‌ها، در صورت وجود شواهد کافی، طرح ترمیم پیشنهاد می‌شود. بدون <code>--apply</code> هیچ تغییری روی دیسک نوشته نمی‌شود.

این برنامه با <bdi dir="ltr">Python 3.8+</bdi> و بدون وابستگی بیرونی اجرا می‌شود. هدف اصلی آن ویندوز و دسترسی مستقیم به <code>\\.\PhysicalDriveN</code> است، اما روی لینوکس (<code>/dev/sdX</code>) و فایل‌های ایمیج خام نیز کار می‌کند. پیام‌ها به‌طور پیش‌فرض فارسی‌اند؛ برای انگلیسی از <code>--lang en</code> استفاده کنید.

### رویکرد

پیدا کردن یک امضا به‌تنهایی اجازهٔ نوشتن نیست:

~~~text
Scanner → Evidence Builder → Write Gate → Patch Transaction → Journal
خواندن     جمع‌آوری شواهد     کنترل نوشتن    اعمال تغییر            بازگردانی
~~~

هر اقدام ترمیمی باید شواهد مستقل و قابل‌بررسی داشته باشد. اگر اثبات کافی وجود نداشته باشد، ابزار از ترمیم خودکار خودداری می‌کند.

### قابلیت‌ها

- شناسایی طرح‌های پارتیشن <bdi dir="ltr">GPT، MBR، superfloppy و RAW</bdi>.
- شناسایی فایل‌سیستم‌های <bdi dir="ltr">NTFS، ReFS، exFAT، FAT12/16/32، ext2/3/4، XFS، Btrfs، Linux swap، LVM2، HFS+، APFS، ISO9660، VMFS و BitLocker</bdi>.
- ارزیابی پارتیشن با تکیه بر جدول پارتیشن، سازگاری بوت‌سکتور، نسخهٔ پشتیبان و طول اثبات‌پذیر ولوم. جزئیات با <code>--explain</code> نمایش داده می‌شود.
- اسکن عمیق برای یافتن ساختارهایی که جدول پارتیشن توصیف نمی‌کند.
- بررسی عمق آسیب با <code>--triage</code>: نمونه‌برداری از ولوم، بررسی ابتدا و انتهای آن و جست‌وجوی ساختارهای باقی‌مانده.
- ایمیج‌گیری فارنزیک با تلاش مجدد برای خواندن و ثبت محدوده‌های خوانده‌نشده در <code>.badmap.json</code>.
- ساخت Journal پیش از نوشتن و بازگردانی بایت‌به‌بایت با <code>--undo</code>.
- آزمایش داخلی روی ایمیج‌های ساختگی، بدون دسترسی به دیسک واقعی.

### محدودیت‌های مهم

- ساختارهای <bdi dir="ltr">ReFS</bdi> در سطح سکتور نوشته نمی‌شوند؛ ابزار فقط شواهد جمع می‌کند و ممکن است <code>refsutil salvage</code> یا ابزار تخصصی بازیابی را پیشنهاد دهد.
- بازسازی دیسک پویا (<code>LDM</code>) یا <bdi dir="ltr">Storage Spaces</bdi> انجام نمی‌شود؛ بازسازی جدول پارتیشن، ولوم منطقی را برنمی‌گرداند.
- بازیابی داده از ولومی که واقعاً بازنویسی شده، ممکن نیست. گزارش ابزار فقط به تشخیص وضعیت و انتخاب گام بعدی کمک می‌کند.
- آنتروپی بالا به‌تنهایی نشانهٔ خرابی نیست؛ فایل‌های فشرده و مخزن‌های بکاپ نیز آنتروپی بالا دارند.

### شروع سریع

~~~powershell
# ویندوز؛ PowerShell را با دسترسی Administrator اجرا کنید.
chcp 65001
python diskdoctor.py --self-test
python diskdoctor.py --list
python diskdoctor.py --auto --all
~~~

~~~bash
# لینوکس
sudo python3 diskdoctor.py --disk /dev/sdb --scan --explain --triage

# فایل ایمیج خام
python3 diskdoctor.py --disk /path/to/flat.img --scan --explain
~~~

راهنمای کامل:

~~~text
python diskdoctor.py --help-full
~~~

### سطح‌های مجوز ترمیم

| سطح | توضیح | نیازمندی |
|---|---|---|
| <code>SAFE_RESTORE</code> | کپی ساختار معتبرِ موجود روی همان دیسک، بدون حدس‌زدن. | <code>--apply</code> |
| <code>INFERRED_REBUILD</code> | بازسازی ساختار از روی شواهد. | <code>--apply --allow-inferred</code> |
| <code>BLOCKED</code> | ترمیم انجام نمی‌شود و دلیل آن گزارش می‌شود. | فقط <code>--force</code> می‌تواند آن را دور بزند. |

<code>--force</code> خطرناک است و می‌تواند مسدودکننده‌های ایمنیِ سطح دیسک را نادیده بگیرد. آن را فقط پس از تهیهٔ ایمیج و بررسی مستقل همهٔ شواهد استفاده کنید.

### روند پیشنهادی

~~~powershell
# 1. بررسی ابزار و فهرست دیسک‌ها
python diskdoctor.py --self-test
python diskdoctor.py --list

# 2. فقط‌خواندنی: ساختار، شواهد و عمق آسیب
python diskdoctor.py --disk 3 --scan --explain --triage --json report.json

# 3. پیش از هر ترمیم، ایمیج بگیرید
python diskdoctor.py --disk 3 --image-out D:\img\disk3.img

# 4. ابتدا پیش‌نمایش؛ فقط در صورت اطمینان اجرا کنید
python diskdoctor.py --disk 3 --action gpt-restore-primary
python diskdoctor.py --disk 3 --action gpt-restore-primary --apply

# 5. بازگردانی در صورت نیاز
python diskdoctor.py --undo diskdoctor_backups\journal_XXXX.json
~~~

### آزمون و ایمنی

<code>--self-test</code> ایمیج‌های ساختگیِ <bdi dir="ltr">MBR، GPT، NTFS، exFAT، FAT32 و ReFS</bdi> می‌سازد و مسیرهای تشخیص، امتیازدهی شواهد، کنترل نوشتن، بازگردانی و ایمیج‌گیری را بررسی می‌کند. این آزمون به دیسک واقعی دست نمی‌زند.

- حالت پیش‌فرض همیشه فقط‌خواندنی است.
- پیش از هر <code>--apply</code>، از دیسک ایمیج بگیرید.
- اگر دیسک صدای غیرعادی می‌دهد یا وضعیت <bdi dir="ltr">SMART</bdi> نامطلوب است، ترمیم ساختاری را متوقف کنید و سراغ بازیابی داده بروید.
- ترمیم ساختار، دادهٔ ازدست‌رفته را برنمی‌گرداند. در صورت آسیب به فرادادهٔ فایل‌سیستم، بازیابی در سطح فایل لازم است.

</div>

---

<div dir="ltr" align="left" lang="en">

## English

**DiskDoctor** is a single-file Python utility for forensic disk inspection and evidence-based repair planning. It is intended for cases where a disk or virtual-disk change leaves a partition layout or filesystem unreadable.

> [!WARNING]
> This project is an experience-based reference and an aid for initial investigation. It does not guarantee data recovery or the safety of any action. You are solely responsible for data loss, damage, and every command you run. Review the findings, create an image, and confirm the target and expected outcome before permitting any write.

### What it does

DiskDoctor first answers three questions:

1. What partition scheme does the disk use?
2. What filesystem is present on each partition?
3. How deep is the damage, and is there sufficient evidence for repair?

Only after that analysis does it offer a repair plan, and only when the evidence supports it. Nothing is written unless you explicitly add <code>--apply</code>.

The tool runs on Python 3.8+ with no third-party dependencies. Its primary target is Windows with raw <code>\\.\PhysicalDriveN</code> access, but it also works on Linux (<code>/dev/sdX</code>) and raw disk-image files. Interface messages default to Persian; use <code>--lang en</code> for English.

### Approach

Finding a signature is not treated as permission to write:

~~~text
Scanner → Evidence Builder → Write Gate → Patch Transaction → Journal
read       collect evidence   decide writes  apply change         undo safely
~~~

Every repair action needs independent, inspectable evidence. If proof is missing, the tool declines automatic repair.

### Capabilities

- Detects GPT, MBR, superfloppy, and RAW partition layouts.
- Detects NTFS, ReFS, exFAT, FAT12/16/32, ext2/3/4, XFS, Btrfs, Linux swap, LVM2, HFS+, APFS, ISO9660, VMFS, and BitLocker.
- Scores partition candidates using partition-table evidence, boot-sector consistency, backup copies, and provable volume length. Use <code>--explain</code> to inspect the evidence.
- Performs deep scans for structures missed by, or inconsistent with, a partition table.
- Uses <code>--triage</code> to assess damage depth by sampling the volume, examining its beginning and end, and searching for surviving structures.
- Creates forensic images with read retries, explicit unreadable-range reporting, and a <code>.badmap.json</code> file.
- Writes a journal before every change and can reverse changes byte-for-byte with <code>--undo</code>.
- Runs internal tests against synthetic images without touching a real disk.

### Important limitations

- DiskDoctor never writes ReFS structures at the sector level. It gathers evidence and may point you to <code>refsutil salvage</code> or a specialist recovery tool.
- It does not reconstruct dynamic disks (LDM) or Storage Spaces. Rebuilding a partition table does not restore logical volumes.
- It cannot recover data from a genuinely overwritten volume. Its report helps identify the condition and choose the next step.
- High entropy alone is not evidence of damage: compressed backup repositories can also have high entropy.

### Quick start

~~~powershell
# Windows: run PowerShell as Administrator.
chcp 65001
python diskdoctor.py --self-test
python diskdoctor.py --list
python diskdoctor.py --auto --all
~~~

~~~bash
# Linux
sudo python3 diskdoctor.py --disk /dev/sdb --scan --explain --triage

# Raw disk image
python3 diskdoctor.py --disk /path/to/flat.img --scan --explain
~~~

For the complete command reference:

~~~text
python diskdoctor.py --help-full
~~~

### Repair permissions

| Class | Meaning | Requires |
|---|---|---|
| <code>SAFE_RESTORE</code> | Copies a valid structure that already exists on the same disk. No inference. | <code>--apply</code> |
| <code>INFERRED_REBUILD</code> | Rebuilds a structure from evidence. | <code>--apply --allow-inferred</code> |
| <code>BLOCKED</code> | The repair is declined and the reason is reported. | Only <code>--force</code> can bypass this. |

<code>--force</code> is dangerous and can override disk-level safety blockers. Use it only after imaging the disk and independently validating every relevant finding.

### Suggested workflow

~~~powershell
# 1. Verify the tool and list disks
python diskdoctor.py --self-test
python diskdoctor.py --list

# 2. Read-only inspection: layout, evidence, and damage depth
python diskdoctor.py --disk 3 --scan --explain --triage --json report.json

# 3. Image the disk before attempting any repair
python diskdoctor.py --disk 3 --image-out D:\img\disk3.img

# 4. Preview first; apply only when you are certain
python diskdoctor.py --disk 3 --action gpt-restore-primary
python diskdoctor.py --disk 3 --action gpt-restore-primary --apply

# 5. Undo if necessary
python diskdoctor.py --undo diskdoctor_backups\journal_XXXX.json
~~~

### Testing and safety

<code>--self-test</code> creates synthetic MBR, GPT, NTFS, exFAT, FAT32, and ReFS images, then exercises detection, evidence scoring, write gating, undo, and imaging. It does not access a real disk.

- The default mode is always read-only.
- Create an image before every <code>--apply</code>.
- If the disk makes unusual noise or has a failing SMART status, stop structural repair and move to data recovery.
- Structural repair does not restore lost data. If filesystem metadata is damaged, file-level recovery may be required.

</div>

---

## License

MIT — see [LICENSE](LICENSE).
