# DiskDoctor

<div dir="rtl" align="right" lang="fa">

**اسکنر فارنزیک دیسک و موتور ترمیم مبتنی بر شواهد؛ یک فایل پایتون، بدون وابستگی.**

</div>

<div dir="ltr" align="left" lang="en">

**Forensic disk scanner and evidence-based repair engine in one dependency-free Python file.**

</div>

---

<div dir="rtl" align="right" lang="fa">

## فارسی

### چرا این ابزار ساخته شد

DiskDoctor از یک کار واقعی بازیابی داده بیرون آمد: چند VMDK که اصلاح شده و دوباره در ویندوز Attach شده بودند؛ یکی RAW شده بود و دیگری، یک فایل بکاپ Veeam (`.vbk`) را خراب می‌خواند. ابزار برای پاسخ به سه پرسش ساخته شده است: **این دیسک چه طرح پارتیشن‌بندی‌ای دارد، چه فایل‌سیستمی روی آن قرار دارد و خرابی تا چه اندازه عمیق است؟** سپس، و جداگانه، بررسی می‌کند که آیا نوشتن روی دیسک اصلاً امن است یا نه.

یک فایل، Python 3.8+ و **بدون هیچ پکیج بیرونی**. روی ویندوز (هدف اصلی: دسترسی خام به `\\.\PhysicalDriveN`)، لینوکس (`/dev/sdX`) یا مستقیماً روی فایل ایمیج خام اجرا می‌شود.

پیام‌های ابزار به‌صورت پیش‌فرض فارسی است (`--lang en` برای انگلیسی).

### چرا معماری‌اش این‌طور طراحی شده

بیشتر ابزارهای ترمیم دیسک یا بدون توضیحِ چراییِ ایمن‌بودن، چیزی را تغییر می‌دهند، یا امضاهای خام را نمایش می‌دهند و تصمیم‌گیری را کاملاً به کاربر واگذار می‌کنند. وقتی داده‌ها در یک مخزنِ بکاپِ تولیدی Veeam هستند و هر نوشتن تصمیمی یک‌طرفه است، هیچ‌کدام کافی نیست.

DiskDoctor سه لایه را کاملاً از هم جدا نگه می‌دارد:

```
Scanner  →  Evidence Builder  →  Write Gate  →  Patch Transaction  →  Journal
(خواندن)     (امتیازدهی، نه تصمیم)   (قواعد سخت)    (fsync قبل از نوشتن)   (برگشت بایت‌به‌بایت)
```

هیچ اقدام ترمیمی حق ندارد خودش تصمیم بگیرد که یک کاندید قابل اعتماد است. از لایه شواهد می‌پرسد، که یا اثبات برمی‌گرداند یا امتناع می‌کند — وقتی اثبات نباشد، هیچ fallback نرمی در کار نیست.

### ابزار چه کاری می‌کند

- **تشخیص** طرح‌های GPT / MBR / superfloppy / RAW، و فایل‌سیستم‌های NTFS، ReFS، exFAT، FAT12/16/32، ext2/3/4، XFS، Btrfs، Linux swap، LVM2، HFS+، APFS، ISO9660، VMFS، BitLocker.
- **امتیازدهی هر پارتیشن کاندید** بر اساس سیگنال‌های مستقل و قابل بازرسی (`--explain` همه را چاپ می‌کند): آیا از جدول پارتیشن آمده، آیا فیلدهای BPB بوت‌سکتورش با هم سازگارند، آیا نسخه آینه‌ای وجود دارد و مطابقت دارد، آیا طول اعلامی ولوم واقعاً از یک منبع روی دیسک اثبات‌پذیر است — نه صرفاً «یک امضا اینجا دیده شد».
- **هیچ‌وقت طول پارتیشن را حدس نمی‌زند.** یک امضای فایل‌سیستم به‌تنهایی برای اعتماد به یک آفست کافی نیست؛ یک بوت‌سکتور آینه‌ی تنها (مثلاً از یک ولوم NTFS نابودشده) عمداً چک می‌شود تا با شروع یک ولوم جدید اشتباه گرفته نشود.
- **بدون اثبات، نمی‌نویسد.** هر ترمیم یا `SAFE_RESTORE` است (کپی یک ساختار معتبر موجود روی همین دیسک — GPT پشتیبان → اصلی، یک بوت‌سکتور آینه اعتبارسنجی‌شده) یا `INFERRED_REBUILD` (سنتز یک جدول از صفر، که علاوه بر `--apply` به `--allow-inferred` صریح نیاز دارد). blockerهای سراسری دیسک — GPTی که هندسه‌اش با اندازه واقعی دیسک نمی‌خواند، یک فایل کانتینر به‌جای دیسک خام، یک دیسک سیستمی — هر سنتزی را کاملاً متوقف می‌کنند.
- **تشخیص عمق خرابی** (`--triage`) به‌جای فقط گفتن «بوت‌سکتور نیست»: سکتورهای اول را می‌خواند، انتهای ولوم را برای ساختارهای بازمانده می‌گردد، کل پارتیشن را نمونه‌برداری می‌کند و نقشه خرابی می‌سازد، رو به جلو برای اولین ساختار قابل‌بازیابی پویش می‌کند، و — نکته کلیدی — می‌تواند با یک **ولوم سالمِ کنترل** مقایسه کند تا آنتروپی خام با شاهد بازنویسی اشتباه گرفته نشود (یک repository پر از بکاپ فشرده، سالم یا خراب، آنتروپی بالا دارد).
- **حالت یک‌ضرب** (`--auto`): همه دیسک‌ها را اسکن کن، فقط جایی که جدول نتواند دیسک را توصیف کند اسکن عمیق بزن، هر چیزی که سالم اثبات نشده را triage کن، خودکار یک ولوم کنترل انتخاب کن، یک گزارش متنی و یک JSON بنویس. هیچ بایتی روی هیچ دیسکی نوشته نمی‌شود.
- **Journal قبل از نوشتن.** Journal قبل از تغییر اولین بایت ساخته و fsync می‌شود، با وضعیت هر patch جداگانه (`pending` → `done`). یک crash وسط نوشتن، Journalی برجا می‌گذارد که دقیقاً می‌گوید چه چیزی نوشته شده، و `--undo` آن را بایت‌به‌بایت برمی‌گرداند — حتی نسخه نیمه‌کاره.
- **ایمیج‌گیری فارنزیک**، نه بی‌صدا. خطای خواندن retry می‌شود، بعد به سطح سکتور نزول می‌کند؛ هر چیزی که هنوز خوانده نشود در یک `.badmap.json` صریح ثبت می‌شود با یک الگوی قابل‌تشخیص — هرگز یک صفر بی‌صدا که ممکن است با داده واقعی اشتباه شود.
- **خودش را تست می‌کند** روی ایمیج‌های ساختگی که از روی مشخصات فنی خود فرمت‌ها ساخته شده‌اند (نه از روی فرض‌های خود پارسر) — به بخش [تست](#تست) نگاه کن.

### آنچه عمداً انجام نمی‌دهد

- هیچ ساختار ReFS هیچ‌وقت نوشته نمی‌شود. ترمیم ReFS در سطح سکتور امتناع می‌شود؛ DiskDoctor شواهد جمع می‌کند (شامل یک نسخه‌ی volume header نزدیک انتهای ولوم، و superblockهای تکراری `SUPB`/`CHKP`) و تو را به `refsutil salvage` هدایت می‌کند — با یک چک سازگاری نسخه build، چون سقف نسخه ReFS که `refsutil` می‌شناسد به build ویندوزی که از آن آمده وابسته است، و پیام شکستش («فایل‌سیستم شناخته‌شده نیست») وقتی علت واقعی عدم تطابق نسخه است نه خرابی، گمراه‌کننده است.
- بازسازی دیسک داینامیک (LDM) یا Storage Spaces نیست — بازسازی جدول پارتیشن، ولوم‌های منطقی را برنمی‌گرداند.
- بازیابی داده از ولومی که واقعاً بازنویسی شده نیست. اگر شواهد بگویند بدنه ولوم بازنویسی شده (نه فقط بوت‌سکتورش)، DiskDoctor همین را می‌گوید و به علت محتمل اشاره می‌کند (مثلاً نگاشت غلط extent در VMDK) به‌جای اینکه وانمود کند ترمیم ممکن است.

### شروع سریع

```powershell
# ویندوز، با دسترسی Administrator
chcp 65001
python diskdoctor.py --self-test          # ۱۵۰+ تست ساختگی، به هیچ دیسک واقعی دست نمی‌زند
python diskdoctor.py --list               # فهرست دیسک‌ها
python diskdoctor.py --auto --all         # فقط خواندن، همه‌چیز، یک گزارش متنی+JSON
```

```bash
# لینوکس
sudo python3 diskdoctor.py --disk /dev/sdb --scan --explain --triage

# مستقیم روی فایل ایمیج خام، بدون نیاز به دسترسی بالا
python3 diskdoctor.py --disk /path/to/flat.img --scan --explain
```

راهنمای کامل همه سوییچ‌ها داخل خود ابزار است:

```
python diskdoctor.py --help-full
```

### دروازهٔ نوشتن، به‌طور دقیق

| کلاس | معنی | نیاز به |
|---|---|---|
| `SAFE_RESTORE` | منبع، یک ساختار معتبر موجود روی همین دیسک است. بدون استنتاج. | `--apply` |
| `INFERRED_REBUILD` | ساختار از روی شواهد سنتز می‌شود. | `--apply --allow-inferred` |
| `BLOCKED` | اجرا نمی‌شود و دلیل دقیق آن چاپ می‌شود. | (فقط `--force` از این محدودیت عبور می‌کند؛ این گزینه blockerهای سراسری دیسک را هم نادیده می‌گیرد.) |

اقدام‌های ترمیمی:

`gpt-restore-primary`، `gpt-restore-backup`، `gpt-fix-crc`، `gpt-fix-geometry`، `mbr-write-protective`، `mbr-rebuild`، `gpt-rebuild`، `vbr-restore`، `vbr-restore-reverse`، `parttype-fix`، به‌علاوه `chkdsk`، `refsutil`، `rescan` سمت ویندوز.

بازگردانی‌های GPT **بایت‌به‌بایت** هستند: `gpt-restore-primary` آرایه ورودی‌های پشتیبان را عیناً کپی می‌کند و فقط فیلدهای موقعیت (`MyLBA`، `AlternateLBA`، `PartitionEntryLBA`) و CRC را در هدر جایگزین می‌کند — `entry_size`، revision، و بایت‌های reserved هیچ‌وقت از نو ساخته نمی‌شوند.

### روند کاری پیشنهادی

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

### آزمون

```
python diskdoctor.py --self-test
```

ایمیج‌های ساختگی MBR/GPT/NTFS/exFAT/FAT32/ReFS را از روی مشخصات نوشته‌شده می‌سازد (نه از روی چیزی که خود پارسر فرض می‌کند — مثلاً ایمیج تست FAT32 عمداً یک مقدار طعمه در همان آفستی می‌گذارد که یک پارسر باگ‌دار می‌خواند، پس تست فقط وقتی پاس می‌شود که `BPB_BkBootSec` واقعاً از `0x32` خوانده شود)، بعد کل خط لوله را می‌آزماید: تشخیص پارتیشن/فایل‌سیستم، امتیازدهی شواهد، امتناع Write Gate از بازسازی‌های اثبات‌نشده، بازگردانی‌های بایت‌به‌بایت GPT، تراکنش Journal-قبل-از-نوشتن با برگشت نیمه‌کاره بعد از crash، ایمیج‌گیری فارنزیک با خطای خواندن تزریق‌شده، و منطق کنترل-آنتروپی triage در برابر هم یک ولوم واقعاً بازنویسی‌شده و هم یک ولوم سالمی که صرفاً پر از داده فشرده است. هیچ‌چیز در این مجموعه به دیسک واقعی دست نمی‌زند.

### نکات ایمنی

- پیش‌فرض همیشه فقط-خواندنی است. بدون `--apply` هیچ‌چیز نوشته نمی‌شود.
- قبل از هر `--apply` اول دیسک را ایمیج بگیر (`--image-out`).
- اگر دیسک صدای غیرعادی می‌دهد یا SMART خراب است، متوقف شو — مستقیم برو سراغ بازیابی داده، نه ترمیم ساختار.
- ترمیم ساختار، *ساختار* را برمی‌گرداند نه داده را. اگر متادیتای خود فایل‌سیستم رفته باشد، قدم بعدی بازیابی سطح فایل است، نه تلاش ترمیم دیگر.

</div>

---

<div dir="ltr" align="left" lang="en">

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

### Quick start

```powershell
# Windows, Run as Administrator
chcp 65001
python diskdoctor.py --self-test          # 150+ synthetic tests, touches no real disk
python diskdoctor.py --list               # enumerate disks
python diskdoctor.py --auto --all         # read-only, everything, one text+JSON report
```

```bash
# Linux
sudo python3 diskdoctor.py --disk /dev/sdb --scan --explain --triage

# Directly on a raw image file, no elevated privileges needed
python3 diskdoctor.py --disk /path/to/flat.img --scan --explain
```

Full switch reference is embedded in the tool itself:

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

</div>

---

<div dir="ltr" align="left" lang="en">

## License

MIT — see [LICENSE](LICENSE).

</div>
