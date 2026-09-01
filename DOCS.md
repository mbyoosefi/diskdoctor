# DiskDoctor — مستندات کامل / Full Documentation

[English](#english) · [فارسی](#فارسی) · [README](README.md)

---

<div dir="rtl" align="right">

## فارسی

### چرا این ابزار ساخته شد

DiskDoctor از دل یک تجربهٔ واقعی در بازیابی داده به وجود آمد: چند دیسک مجازی VMDK پس از اصلاح و اتصال مجدد در ویندوز دچار مشکل شده بودند؛ یکی به حالت RAW درآمده بود و دیگری پشتیبان Veeam با پسوند `.vbk` را خراب نمایش می‌داد. این ابزار به سه پرسش اصلی پاسخ می‌دهد: **دیسک از چه نوع پارتیشن‌بندی استفاده می‌کند، چه فایل‌سیستمی روی آن است و خرابی تا چه اندازه پیش رفته است؟** تنها پس از پاسخ به این پرسش‌ها، ایمنیِ نوشتن روی دیسک بررسی می‌شود.

DiskDoctor یک فایل پایتون است، با Python 3.8 و نسخه‌های جدیدتر کار می‌کند و **هیچ وابستگی خارجی ندارد**. می‌توانید آن را در ویندوز، لینوکس یا مستقیماً روی یک ایمیج خام اجرا کنید. در ویندوز، مسیر دسترسی خام به دیسک به‌شکل `\\.\PhysicalDriveN` است.

پیام‌های ابزار به‌صورت پیش‌فرض فارسی است (`--lang en` برای انگلیسی).

### چرا این معماری انتخاب شده است

بسیاری از ابزارهای تعمیر دیسک یا بدون توضیحِ کافی تغییر ایجاد می‌کنند، یا فقط امضاهای خام را نشان می‌دهند و تصمیم نهایی را کاملاً بر عهدهٔ کاربر می‌گذارند. برای داده‌های یک مخزن عملیاتی Veeam، هیچ‌یک از این رویکردها کافی نیست؛ زیرا یک نوشتن نادرست ممکن است راه بازگشت نداشته باشد.

DiskDoctor سه لایه را کاملاً از هم جدا نگه می‌دارد:

```
Scanner  →  Evidence Builder  →  Write Gate  →  Patch Transaction  →  Journal
(خواندن)     (امتیازدهی، نه تصمیم)   (قواعد سخت)    (fsync قبل از نوشتن)   (برگشت بایت‌به‌بایت)
```

هیچ عملیات تعمیری خودش دربارهٔ قابل‌اعتماد بودن یک گزینه تصمیم نمی‌گیرد. هر عملیات باید از لایهٔ شواهد تأیید بگیرد؛ این لایه یا دلیل کافی ارائه می‌کند یا درخواست را رد می‌کند. اگر شواهد کافی نباشد، ابزار راه میان‌بُر یا حالت آسان‌گیرانه‌ای ندارد.

### ابزار چه کاری می‌کند

- **طرح پارتیشن و فایل‌سیستم را شناسایی می‌کند.** فرمت‌های پشتیبانی‌شده شامل GPT، MBR، superfloppy، RAW، NTFS، ReFS، exFAT، FAT12/16/32، ext2/3/4، XFS، Btrfs، Linux swap، LVM2، HFS+، APFS، ISO9660، VMFS و BitLocker هستند.
- **برای هر پارتیشن احتمالی امتیاز اطمینان می‌سازد.** با `--explain` می‌توانید تمام شواهد را ببینید: آیا پارتیشن در جدول ثبت شده است؟ آیا اطلاعات BPB در بوت‌سکتور با یکدیگر سازگارند؟ آیا نسخهٔ آینه‌ای معتبر وجود دارد؟ و آیا طول ولوم واقعاً از داده‌های روی دیسک قابل اثبات است؟ صرف پیدا کردن یک امضا برای نتیجه‌گیری کافی نیست.
- **اندازهٔ پارتیشن را حدس نمی‌زند.** امضای فایل‌سیستم، به‌تنهایی، یک نقطهٔ شروع معتبر را ثابت نمی‌کند. برای مثال، ابزار بوت‌سکتور آینه‌ایِ جداافتادهٔ یک ولوم NTFS آسیب‌دیده را بررسی می‌کند تا آن را با ابتدای یک ولوم تازه اشتباه نگیرد.
- **بدون مدرک کافی چیزی نمی‌نویسد.** در حالت `SAFE_RESTORE`، ساختار معتبر موجود روی همان دیسک کپی می‌شود؛ مثلاً نسخهٔ پشتیبان GPT به نسخهٔ اصلی بازگردانده می‌شود. در حالت `INFERRED_REBUILD`، جدول از شواهد موجود بازسازی می‌شود و علاوه بر `--apply` به گزینهٔ `--allow-inferred` نیاز دارد. اگر هندسهٔ GPT با اندازهٔ واقعی دیسک هم‌خوان نباشد، هدف یک فایل کانتینر باشد یا دیسک سیستمی انتخاب شده باشد، بازسازی متوقف می‌شود.
- **شدت خرابی را بررسی می‌کند** (`--triage`)؛ نه اینکه فقط بگوید «بوت‌سکتور پیدا نشد». ابتدا و انتهای ولوم را برای ساختارهای باقی‌مانده می‌خواند، از سراسر پارتیشن نمونه می‌گیرد، نقشهٔ خرابی می‌سازد و به‌دنبال نخستین ساختار قابل‌بازیابی می‌گردد. همچنین می‌تواند نتیجه را با یک **ولوم سالمِ مرجع** مقایسه کند تا آنتروپی بالای داده‌های فشرده با نشانهٔ بازنویسی اشتباه گرفته نشود.
- **حالت خودکار** (`--auto`) همهٔ دیسک‌ها را بررسی می‌کند. فقط هنگامی که جدول پارتیشن نتواند وضعیت دیسک را توضیح دهد، اسکن عمیق اجرا می‌شود. موارد مشکوک ارزیابی می‌شوند، یک ولوم سالم به‌عنوان مرجع انتخاب می‌شود و گزارش متنی و JSON تولید می‌شود. این حالت کاملاً فقط‌خواندنی است.
- **پیش از نوشتن، گزارش بازگشت ایجاد می‌کند.** Journal پیش از تغییر اولین بایت ایجاد و با `fsync` روی دیسک ثبت می‌شود. وضعیت هر patch جداگانه ثبت می‌شود (`pending` → `done`). اگر هنگام نوشتن برنامه متوقف شود، `--undo` حتی تغییر نیمه‌تمام را نیز بایت‌به‌بایت بازمی‌گرداند.
- **ایمیج‌گیری را با ثبت خطا انجام می‌دهد.** خطای خواندن ابتدا دوباره امتحان می‌شود و در صورت لزوم خواندن تا سطح سکتور ادامه پیدا می‌کند. بخش‌های خوانده‌نشده در فایل `.badmap.json` ثبت می‌شوند و با الگویی مشخص پر می‌شوند؛ هیچ‌گاه به‌طور پنهان صفرگذاری نمی‌شوند.
- **خودآزمایی دارد.** ایمیج‌های آزمایشی از روی مشخصات فنی فرمت‌ها ساخته می‌شوند، نه بر پایهٔ فرض‌های پارسر. جزئیات بیشتر در بخش [تست](#تست) آمده است.

### آنچه عمداً انجام نمی‌دهد

- هیچ ساختار ReFS نوشته نمی‌شود. ترمیم ReFS در سطح سکتور رد می‌شود؛ DiskDoctor شواهد، از جمله یک نسخهٔ volume header نزدیک انتهای ولوم و superblockهای تکراری `SUPB`/`CHKP`، را گردآوری می‌کند و کاربر را به `refsutil salvage` هدایت می‌کند. همچنین سازگاری نسخهٔ build بررسی می‌شود، زیرا حداکثر نسخهٔ ReFS قابل شناسایی توسط `refsutil` به build ویندوز وابسته است. در صورت ناسازگاری نسخه، پیام «فایل‌سیستم شناخته‌شده نیست» می‌تواند گمراه‌کننده باشد؛ علت لزوماً خرابی نیست.
- بازسازی دیسک‌های پویا (LDM) یا Storage Spaces انجام نمی‌شود؛ بازسازی جدول پارتیشن، ولوم‌های منطقی را بازنمی‌گرداند.
- بازیابی داده از ولومی که واقعاً بازنویسی شده است در محدودهٔ این ابزار نیست. اگر شواهد نشان دهند بدنهٔ ولوم، نه فقط بوت‌سکتور آن، بازنویسی شده است، DiskDoctor نتیجه و علت احتمالی (برای نمونه، نگاشت نادرست extent در VMDK) را اعلام می‌کند و امکان ترمیم را وانمود نمی‌کند.

### راهنمای کامل گزینه‌ها

```
python diskdoctor.py --help-full
```

### سازوکار Write Gate

| کلاس | معنی | نیاز به |
|---|---|---|
| `SAFE_RESTORE` | منبع، یک ساختار معتبر موجود روی همین دیسک است. بدون استنتاج. | `--apply` |
| `INFERRED_REBUILD` | ساختار از روی شواهد سنتز می‌شود. | `--apply --allow-inferred` |
| `BLOCKED` | امتناع، با دلیل دقیق چاپ‌شده. | (هیچ‌چیز این را دور نمی‌زند جز `--force`، که blockerهای سراسری دیسک را هم رد می‌کند) |

اقدام‌های ترمیمی:

`gpt-restore-primary`، `gpt-restore-backup`، `gpt-fix-crc`، `gpt-fix-geometry`، `mbr-write-protective`، `mbr-rebuild`، `gpt-rebuild`، `vbr-restore`، `vbr-restore-reverse`، `parttype-fix`، به‌علاوه `chkdsk`، `refsutil`، `rescan` سمت ویندوز.

بازگردانی‌های GPT **بایت‌به‌بایت** هستند: `gpt-restore-primary` آرایه ورودی‌های پشتیبان را عیناً کپی می‌کند و فقط فیلدهای موقعیت (`MyLBA`، `AlternateLBA`، `PartitionEntryLBA`) و CRC را در هدر جایگزین می‌کند — `entry_size`، revision، و بایت‌های reserved هیچ‌وقت از نو ساخته نمی‌شوند.

### گردش‌کار پیشنهادی

```powershell
python diskdoctor.py --self-test
python diskdoctor.py --list
python diskdoctor.py --disk 3 --scan --explain --triage --json report.json
python diskdoctor.py --disk 3 --image-out D:\img\disk3.img      # قبل از هر --apply
python diskdoctor.py --disk 3 --action gpt-restore-primary               # پیش‌نمایش
python diskdoctor.py --disk 3 --action gpt-restore-primary --apply       # اجرا
python diskdoctor.py --undo diskdoctor_backups\journal_XXXX.json         # اگر غلط بود
```

یا فقط:

```powershell
python diskdoctor.py --auto --all
```

### تست

```
python diskdoctor.py --self-test
```

این مجموعه ایمیج‌های مصنوعی MBR/GPT/NTFS/exFAT/FAT32/ReFS را بر اساس مشخصات مکتوب می‌سازد، نه بر پایهٔ فرض‌های پارسر. برای نمونه، ایمیج آزمایشی FAT32 عمداً مقداری فریبنده را در آفستی قرار می‌دهد که پارسرِ معیوب ممکن است بخواند؛ بنابراین آزمون فقط زمانی موفق است که `BPB_BkBootSec` واقعاً از آفست `0x32` خوانده شود.

سپس تمام زنجیرهٔ پردازش بررسی می‌شود: تشخیص پارتیشن و فایل‌سیستم، امتیازدهی شواهد، رد بازسازی‌های اثبات‌نشده توسط Write Gate، بازگردانی بایت‌به‌بایت GPT، تراکنش ثبت‌شده پیش از نوشتن و بازگشت از توقف نیمه‌کاره، ایمیج‌گیری فارنزیک با خطاهای خواندن تزریق‌شده و منطق کنترل آنتروپی در `triage`. آزمون‌ها هم یک ولوم واقعاً بازنویسی‌شده و هم ولوم سالمی را که صرفاً دادهٔ فشرده دارد پوشش می‌دهند. هیچ‌یک از این آزمون‌ها به دیسک واقعی دسترسی ندارد.

### کدهای خروج

| کد | معنی |
|---|---|
| 0 | موفق |
| 1 | خطای عمومی |
| 2 | آرگومان نامعتبر |
| 3 | دسترسی رد شد |
| 4 | هدف پیدا نشد |
| 5 | لغو توسط کاربر |
| 6 | self-test شکست خورد |
| 7 | نوشتن توسط gate رد شد |

### نکات ایمنی

- پیش‌فرض همیشه فقط-خواندنی است. بدون `--apply` هیچ‌چیز نوشته نمی‌شود.
- پیش از هر `--apply`، ابتدا از دیسک ایمیج تهیه کنید (`--image-out`).
- اگر دیسک صدای غیرعادی تولید می‌کند یا وضعیت SMART آن نامطلوب است، عملیات را متوقف کنید و مستقیماً سراغ بازیابی داده بروید، نه ترمیم ساختار.
- ترمیم ساختاری، *ساختار* را بازمی‌گرداند، نه داده را. اگر فرادادهٔ فایل‌سیستم از بین رفته باشد، گام بعدی بازیابی در سطح فایل است، نه انجام یک ترمیم ساختاری دیگر.

### سلب مسئولیت

این ابزار «همان‌گونه که هست» ارائه می‌شود و استفاده از آن کاملاً بر عهدهٔ کاربر است. عملیات ترمیمی، به‌ویژه دستورهای دارای `--apply` یا `--force`، ممکن است به از دست رفتن داده یا برگشت‌ناپذیر شدن تغییرات منجر شوند. پیش از نوشتن روی هر دیسک، از آن ایمیج یا نسخهٔ پشتیبان کامل تهیه کنید. نویسندگان و مشارکت‌کنندگان پروژه در قبال خسارت، از دست رفتن داده یا اختلال ناشی از استفاده از این ابزار مسئولیتی ندارند.

</div>

---

## English

### Why this exists

DiskDoctor grew out of a real recovery job: VMware VMDKs that had been repaired and re-attached in Windows, one of which had gone RAW and another whose Veeam `.vbk` backup was reading corrupt. It answers three questions for a disk you're not sure about — *what partition scheme is this, what filesystem is on it, and how deep does the damage go* — and only then, separately, asks whether it's safe to write anything.

Single file, Python 3.8+, **zero third-party dependencies**. Runs on Windows (primary target — raw `\\.\PhysicalDriveN` access), Linux (`/dev/sdX`), or directly against a raw disk image.

Tool messages default to Persian (`--lang en` for English).

### Why the architecture is shaped this way

Most disk-repair tools either (a) fix things without telling you why they think it's safe, or (b) dump raw signatures at you and leave the judgment call to you. Neither is good enough when the data is a production Veeam repository and every write is a one-way door.

DiskDoctor keeps three concerns strictly apart:

```
Scanner  →  Evidence Builder  →  Write Gate  →  Patch Transaction  →  Journal
(read)      (score, don't act)   (hard rules)    (fsync before write)  (byte-exact undo)
```

A repair action never gets to decide for itself that a candidate looks trustworthy. It asks the evidence layer, which either hands back proof or refuses — there is no soft fallback when proof is missing.

### What it does

- **Detects** GPT / MBR / superfloppy / RAW partition schemes, and NTFS, ReFS, exFAT, FAT12/16/32, ext2/3/4, XFS, Btrfs, Linux swap, LVM2, HFS+, APFS, ISO9660, VMFS, BitLocker.
- **Scores every candidate partition** on independent, inspectable signals (`--explain` prints all of them): does it come from a partition table, does its boot sector's own BPB fields agree with each other, does a backup copy exist and match, is the declared volume length actually provable from a source on disk — not just "a signature was seen here".
- **Never guesses a partition's length.** A filesystem signature alone is not enough to trust an offset; a lone backup boot sector (e.g. from a destroyed NTFS volume) is specifically checked so it isn't mistaken for the start of a new volume.
- **Refuses writes without proof.** Every repair is either `SAFE_RESTORE` (copying an existing, valid structure already on the disk — GPT backup → primary, a validated mirror boot sector) or `INFERRED_REBUILD` (synthesizing a table from scratch, which needs an explicit `--allow-inferred` on top of `--apply`). Disk-level blockers — a GPT whose geometry doesn't match the real disk size, a container file instead of a raw disk, a system disk — stop every synthesis outright.
- **Triages damage depth** (`--triage`) instead of just saying "boot sector missing": reads the first sectors, sweeps the volume tail for surviving filesystem structures, samples the whole partition for a damage map, walks forward for the first recoverable structure, and — critically — can compare against a **known-healthy control volume** so raw entropy isn't mistaken for evidence of an overwrite (a repository full of compressed backups is high-entropy *by design*).
- **One-shot mode** (`--auto`): scan every disk, go deep only where the table can't describe the disk, triage everything that isn't provably healthy, pick a control volume automatically, write one text report and one JSON file. Nothing is written to any disk.
- **Journals before writing.** The journal is created and fsynced *before* the first byte changes, with per-patch status (`pending` → `done`). A crash mid-write leaves a journal that says exactly what landed, and `--undo` reverses it byte-for-byte — including a partial one.
- **Images forensically**, not silently. Read failures retry, then descend to sector granularity; anything still unreadable is recorded in an explicit `.badmap.json` with a recognizable fill pattern — never a quiet zero that could be mistaken for real data.
- **Self-tests itself** against synthetic disk images built from the on-disk specifications (not from the parser's own assumptions) — see [Testing](#testing).

### What it deliberately does not do

- No ReFS structure is ever written. ReFS repair is refused at the sector level; DiskDoctor gathers evidence (including a volume-header copy near the end of the volume, and duplicated `SUPB`/`CHKP` superblocks) and routes you to `refsutil salvage` — with a build-version compatibility check, because `refsutil`'s ReFS-version ceiling is tied to the Windows build it shipped with, and its failure message ("volume does not contain a recognized file system") is misleading when the real cause is a version mismatch, not corruption.
- No dynamic disks (LDM) / Storage Spaces reconstruction — rebuilding the partition table does not bring back logical volumes.
- No data recovery from a genuinely overwritten volume. If the evidence says the volume body was overwritten (not just its boot sector), DiskDoctor says so and points at the likely cause (e.g. a wrong VMDK extent mapping) instead of pretending a repair is possible.

### Full switch reference

```
python diskdoctor.py --help-full
```

### The write gate, concretely

| Gate | Meaning | Requires |
|---|---|---|
| `SAFE_RESTORE` | Source is a valid structure that already exists on this disk. No inference. | `--apply` |
| `INFERRED_REBUILD` | Structure is synthesized from evidence. | `--apply --allow-inferred` |
| `BLOCKED` | Refused, with the exact reason printed. | (nothing bypasses this except `--force`, which also overrides disk-level blockers) |

Repair actions:

`gpt-restore-primary`, `gpt-restore-backup`, `gpt-fix-crc`, `gpt-fix-geometry`, `mbr-write-protective`, `mbr-rebuild`, `gpt-rebuild`, `vbr-restore`, `vbr-restore-reverse`, `parttype-fix`, plus the Windows-side `chkdsk`, `refsutil`, `rescan`.

GPT restores are **byte-for-byte**: `gpt-restore-primary` copies the backup's entry array verbatim and transplants only the location fields (`MyLBA`, `AlternateLBA`, `PartitionEntryLBA`) and CRC into the header — `entry_size`, revision, and reserved bytes are never regenerated.

### Recommended workflow

```powershell
python diskdoctor.py --self-test
python diskdoctor.py --list
python diskdoctor.py --disk 3 --scan --explain --triage --json report.json
python diskdoctor.py --disk 3 --image-out D:\img\disk3.img      # before any --apply
python diskdoctor.py --disk 3 --action gpt-restore-primary               # preview
python diskdoctor.py --disk 3 --action gpt-restore-primary --apply       # commit
python diskdoctor.py --undo diskdoctor_backups\journal_XXXX.json         # if wrong
```

Or just:

```powershell
python diskdoctor.py --auto --all
```

### Testing

```
python diskdoctor.py --self-test
```

Builds synthetic MBR/GPT/NTFS/exFAT/FAT32/ReFS images from the written specification (not from what the parser itself assumes — e.g. the FAT32 test image deliberately places a decoy value at the offset a buggy parser would read, so the test only passes if `BPB_BkBootSec` is actually read from `0x32`), then exercises the full pipeline: partition/filesystem detection, evidence scoring, the write gate refusing unproven rebuilds, byte-for-byte GPT restores, journal-before-write with crash-partial undo, forensic imaging with injected read failures, and the triage entropy-control logic against both a genuinely overwritten volume and a healthy one that merely happens to be full of compressed data. Nothing in the suite touches a real disk.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | general error |
| 2 | bad argument |
| 3 | permission denied |
| 4 | target not found |
| 5 | cancelled by user |
| 6 | self-test failed |
| 7 | write refused by the gate |

### Safety notes

- Default is always read-only. Nothing is written without `--apply`.
- Image the disk first (`--image-out`) before any `--apply`.
- If the disk makes unusual noise or SMART is failing, stop — go straight to data recovery, not structural repair.
- Structural repair restores *structure*, not data. If the filesystem's own metadata is gone, the next step is file-level recovery, not another repair attempt.

### Disclaimer

This tool is provided **as is** and is used entirely at your own risk. Repair operations—especially commands using `--apply` or `--force`—can cause data loss or make changes irreversible. Create a complete disk image or backup before writing to any disk. The project authors and contributors are not liable for any damage, data loss, or disruption resulting from use of this tool.

---

## License / مجوز

Released under the [MIT License](LICENSE).
