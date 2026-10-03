#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
================================================================================
DiskDoctor v2.0.0-rc1  —  Forensic scanner + evidence-based repair engine
اسکن فارنزیک و ترمیم مبتنی بر شواهد برای دیسک‌هایی که پس از اصلاح VMDK
در ویندوز Attach/Assign شده‌اند.
================================================================================

تازه در v1.9.5
--------------
* --find-name-file PATH : متن --find-name را از فایل بخوان، درست مثل
  --locate-verify-file. همان مشکل کوتیشن/BOM که برای --locate-verify پیش
  آمد می‌توانست دقیقاً برای --find-name هم اتفاق بیفتد؛ حالا هر دو با یک
  مکانیزم یکسان محافظت می‌شوند.

تازه در v1.9.4
--------------
* رفع باگ: --locate-verify-file یک BOM (Byte Order Mark) احتمالی در ابتدای
  فایل را نادیده نمی‌گرفت. PowerShell با `Out-File -Encoding utf8` همیشه یک
  BOM نامرئی در ابتدای فایل می‌گذارد؛ بدون حذفش، متن جستجو با یک کاراکتر
  نامرئی شروع می‌شد و هیچ‌جای دیسک پیدا نمی‌شد — نتیجه به‌ظاهر «هیچ کاندیدی
  تایید نشد» بود، در حالی که مکانیزم verify کاملاً درست کار می‌کرد. حالا با
  encoding «utf-8-sig» فایل خوانده می‌شود که BOM را در صورت وجود خودکار
  حذف می‌کند.

تازه در v1.9.3
--------------
* --locate-verify-file PATH : متن جستجوی --locate-verify را از یک فایل بخوان
  به‌جای خط فرمان. وقتی متن کوتیشن دوتایی داخلش دارد (مثل الگوی توصیف‌گر
  VMDK: `VMFS "..."`)، PowerShell گاهی آن کوتیشن را درست escape نمی‌کند و
  بقیه سوییچ‌های خط فرمان (از جمله --locate-verify-top-n) را بی‌صدا قورت
  می‌دهد — دقیقاً همین اتفاق افتاد. با خواندن از فایل، هیچ کوتیشن یا کاراکتر
  خاصی از صافی shell عبور نمی‌کند.
      "VMFS `"Active (172.17.1.253)" | Out-File -Encoding utf8 needle.txt
      python diskdoctor.py --disk 3 --locate-vbk ... --locate-verify-file needle.txt

تازه در v1.9.2
--------------
* رفع باگ: --locate-verify-top-n نادیده گرفته می‌شد. تابع امتیازدهی زیرین
  همیشه لیست را به ۲۰ کاندید برتر کوتاه می‌کرد *قبل* از اینکه مرحله تایید
  محتوا آن را ببیند — یعنی هر عددی برای --locate-verify-top-n می‌دادی
  (حتی چند هزار)، فقط همان ۲۰ تای اول واقعاً چک می‌شدند. روی یک repository
  پرتراکم، کاندید درست معمولاً امتیاز آنتروپی‌اش در ۲۰ تای اول نیست، پس این
  باگ می‌توانست باعث شود کاندید واقعی هیچ‌وقت تست نشود. رفع شد و با تست T37
  قفل شد تا تکرار نشود.

تازه در v1.9.1
--------------
* --locate-verify TEXT (کنار --locate-vbk) : روی یک repository پرتراکم، چند
  فایل همسایه می‌توانند دقیقاً همان امتیاز آنتروپی/تراز را داشته باشند —
  چون همه‌شان داده فشرده با شکل مشابه‌اند. امتیازدهی به‌تنهایی در این حالت
  کاندید غلط را رتبه اول می‌دهد. این سوییچ کاندیدهای برتر را با یک پروب
  واقعی (چند مگابایت) تایید می‌کند: آیا متن داده‌شده (مثلاً نام VM) واقعاً
  در همان ابتدای فایل هست یا نه — همان الگویی که هر بار carve موفق واقعی
  را مشخص کرده بود.
      python diskdoctor.py --disk 3 --locate-vbk 93843712:18940297216 \
          --locate-verify "Active (172.17.1.253)"

تازه در v1.9
------------
* --locate-vbk CENTER_LBA:SIZE_BYTES : یافتن نقطه شروع دقیق یک فایل به اندازه
  مشخص (از BackupSize در .vbm) با استفاده از تراز بلوک Veeam (معمولاً 65536
  بایت، از BlockAlignmentSize در همان .vbm) به‌جای حدس خطی از روی margin.
  چون carve کردن ده‌ها یا صدها گیگابایت با margin حدسی گران است و اگر نقطه
  شروع چند بایت جابه‌جا باشد، ابزار بازیابی ویم پیام «Storage version نامعتبر»
  می‌دهد حتی وقتی نسخه سرور دقیقاً همان است — این ابزار چند هزار کاندید
  تراز‌شده را با چند کیلوبایت خواندن در هر کدام امتحان می‌کند و بهترین نقطه
  مرز (جایی که قبل و بعدش با محتوای فایل فرق دارد) را رتبه‌بندی می‌کند. فقط
  خواندن.
      python diskdoctor.py --disk 1 --locate-vbk 93843712:18940297216

تازه در v1.8
------------
* --find-vbm : جستجوی محتوای واقعی فایل .vbm (تگ XML مستند <BackupMeta>،
  نه فقط ورودی دایرکتوری آن). فرمت VBK/VIB خود Veeam منتشر نشده (خود ویم در
  فروم رسمی به این تصریح کرده)، ولی ساختار .vbm مستند است. از روی آن
  FilePath اصلی، BackupSize دقیق به بایت، EncryptionState، JobName و غیره
  استخراج می‌شود — شواهد قطعی‌تر از حدس زدن نام یا اندازه فایل.
      python diskdoctor.py --disk 1 --find-vbm --json vbm.json
* --carve-vbk CENTER_LBA:MARGIN_GIB : استخراج یک محدوده بزرگ و پیوسته اطراف
  یک LBA شناخته‌شده (مثلاً جایی که محتوای .vbk قبلاً با --dump-range تایید
  شده) به یک فایل، برای دادن به Veeam Extract Utility. چون امضای شروع فایل
  VBK مستند نیست، این ابزار حدس دقیق نمی‌زند — margin را به‌اندازه کافی
  بزرگ بگیر تا شروع واقعی فایل حتماً داخل محدوده باشد.
      python diskdoctor.py --disk 1 --carve-vbk 234280000:4 --carve-out ftp.bin

تازه در v1.7.1
--------------
* فیلتر نویز برای رشته‌های استخراج‌شده. داده فشرده/رمزشده دائم رشته‌های کوتاه
  خوانا تولید می‌کند و نام فایل‌های واقعی را در انبوه آشغال گم می‌کرد. حالا
  فقط رشته‌هایی نشان داده می‌شوند که یا یک کلمه واقعی دارند (توکن CamelCase
  با چهار حرف یا بیشتر) یا به پسوند فایل ختم می‌شوند. روی نمونه واقعی:
  ۱۳ نام واقعی از ۱۳ حفظ شد، ۸۲ رشته نویز از ۸۴ حذف شد.
  با --dump-raw-strings همه رشته‌ها بدون فیلتر نشان داده می‌شوند.

تازه در v1.7
------------
* --dump-range LBA:COUNT : استخراج یک محدوده سکتور خام به فایل، به‌علاوه چاپ
  رشته‌های خوانای داخلش (هم ASCII هم UTF-16LE). برای بیرون کشیدن یک ساختار
  کوچک — یک .vbm، یک بوت‌سکتور، یک نود متادیتا — از ولومی که فایل‌سیستمش
  دیگر نمی‌تواند آن را پیدا کند. فقط خواندن.
      python diskdoctor.py --disk 1 --dump-range 9211248:64 --dump-out vbm.bin

تازه در v1.6
------------
* --find-name : جستجوی یک نام فایل در بایت‌های خام دیسک، مستقل از فایل‌سیستم.
  نام فایل‌ها در متادیتای NTFS/ReFS/exFAT به‌صورت UTF-16LE ذخیره می‌شوند، پس
  حتی وقتی ساختارهایی که محل فایل را مشخص می‌کنند نابود شده‌اند، خود نام هنوز
  قابل پیدا شدن است. برای پاسخ به «آیا این فایل اصلاً روی این ولوم بوده؟»
  وقتی هیچ ابزار دیگری نمی‌تواند جواب بدهد. هر دو شکل UTF-16 و ASCII و
  بدون حساسیت به بزرگی/کوچکی حروف. فقط خواندن.
      python diskdoctor.py --disk 1 --find-name "Ftp"

تازه در v1.5.1
--------------
* رفع باگ: سه سوییچ --triage-head-gib، --triage-head-samples و --baseline در
  متن راهنما مستند شده و در کد استفاده می‌شدند ولی هیچ‌وقت به argparse معرفی
  نشده بودند. نتیجه‌اش کرش با AttributeError وسط triage بود. علت پنهان ماندنش:
  همه تست‌ها Namespace خودشان را با _fake_args می‌ساختند و هیچ‌وقت parser واقعی
  را صدا نمی‌زدند. حالا یک تست، تمام args.*هایی که کد می‌خواند را با خروجی
  build_parser() مقایسه می‌کند تا این نوع اختلاف دوباره از قلم نیفتد.

تازه در v1.5
------------
* refsutil سقف نسخه ReFS دارد که به build ویندوزی که از آن آمده وابسته است،
  نه به پرچم‌های خط فرمان. وقتی ولوم از آن سقف بالاتر باشد (مثلاً ReFS 3.14
  با refsutil ساخته‌شده برای حداکثر 3.9)، پیام refsutil با «فایل‌سیستم شناخته
  نشد» گمراه‌کننده است — ولوم را درست شناسایی کرده، فقط رد کرده. ابزار حالا
  این حالت را از روی متن خروجی خود refsutil تشخیص می‌دهد (بدون جدول نسخه
  هاردکد شده که منسوخ می‌شود) و راه‌حل واقعی را نشان می‌دهد: ویندوز جدیدتر،
  ابزار بازیابی مستقل، یا Veeam Support.
* نسخه ReFS در پیشنهاد اقدام، هشدارها، و نتیجه‌گیری triage نمایش داده می‌شود
  تا قبل از اجرای refsutil بشود با winver مقایسه کرد.

تازه در v1.4
------------
* اصلاح یک خطای تشخیصی مهم: v1.3 «آنتروپی بالای بدنه ولوم» را نشانه بازنویسی
  می‌گرفت. یک repository پر از فایل بکاپ فشرده هم دقیقاً همان الگو را می‌دهد،
  چه سالم باشد چه خراب. حالا بدون یک اندازه‌گیری کنترل روی ولوم سالمِ همان
  سیستم، آنتروپی اصلاً به‌عنوان شاهد استفاده نمی‌شود.
* --baseline و انتخاب خودکار کنترل در حالت auto: یک ولوم سالم با همان
  فایل‌سیستم پیدا و با همان تنظیمات اندازه‌گیری می‌شود تا مقایسه واقعی باشد.
* پویش ترتیبی برای یافتن اولین ساختار حالا همیشه اجرا می‌شود. v1.3 دقیقاً
  وقتی که نمونه‌برداری چیزی پیدا نکرده بود آن را رد می‌کرد — یعنی همان جایی
  که بیش از همه لازم بود.
* نقشه متراکم ابتدای ولوم (--triage-head-gib) برای دیدن اینکه بازنویسی
  هدفمند ابتدا تا کجا رفته.

تازه در v1.3
------------
* --auto : یک دستور، همه جواب‌ها. خودش تصمیم می‌گیرد کجا اسکن عمیق لازم است،
  هر ولومی که سالم اثبات نشده را triage می‌کند، برای هر دیسک یک نتیجه‌گیری
  می‌دهد، و همه‌چیز را در یک فایل متنی و یک JSON می‌نویسد. هیچ سوییچی برای
  انتخاب نداری و هیچ بایتی نوشته نمی‌شود.
      python diskdoctor.py --auto --all
      python diskdoctor.py --auto --disk 3

تازه در v1.2
------------
* --triage : یک دستور، جواب کامل. برای هر پارتیشنی که سالم تشخیص داده نشده،
  عمق خرابی را می‌سنجد: سکتور اول، آنتروپی، جستجوی ساختار در انتهای ولوم،
  نقشه خرابی با نمونه‌برداری، پویش مرز، و یک نتیجه‌گیری با گام بعدی.
  همه‌اش فقط-خواندنی.
* ReFS دیگر «بدون آینه» فرض نمی‌شود. ولوم ReFS یک نسخه از volume header را در
  آخرین سکتور خودش نگه می‌دارد؛ v1.1 این را به‌عنوان قاعده سخت رد می‌کرد و
  اشتباه بود. حالا یک سیگنال شواهد است و وقتی تایید شود، طول ولوم را اثبات
  می‌کند. شناسه FSRS هم با جستجو پیدا می‌شود نه آفست ثابت، چون روی دیسک واقعی
  در 0x10 است نه 0x0F که بعضی مراجع می‌گویند.
* اصلاح چند تشخیص غلط که روی دیسک واقعی دیده شد:
    - ورودی 0xEE در Protective MBR با مقدار اشباع 0xFFFFFFFF دیگر «خارج از
      محدوده» شمرده نمی‌شود (قبلاً روی هر دیسک GPT بزرگ یک blocker کاذب می‌ساخت)
    - چک هندسه GPT سمت‌آگاه شد: در هدر پشتیبان، AlternateLBA=1 درست است
    - پارتیشن‌های MSR، BIOS boot، LDM metadata و Storage Spaces عمداً
      فایل‌سیستم ندارند و دیگر «خراب» علامت نمی‌خورند
    - extent_agreement مدل NTFS را به همه تحمیل نمی‌کند؛ ReFS و فایل‌سیستم‌های
      لینوکس لازم نیست تا انتهای پارتیشن کشیده شوند
    - ستون نوع پارتیشن به گزارش برگشت
* --deep-ignore-table : وقتی خود جدول پارتیشن مشکوک است، اسکن عمیق محدوده‌های
  ادعایی آن را هم می‌گردد. بدون این، یک جدول غلط ولوم واقعی داخل خودش را
  پنهان می‌کند.

تفاوت بنیادی با v1.0
--------------------
v1.0 یک اسکنر با ترمیم‌گر heuristic بود: هر چیزی که امضایش شناسایی می‌شد،
کاندید نوشتن بود. v1.1 دو چیز را از هم جدا می‌کند:

    «چه چیزی دیدم»   (Evidence)      از   «اجازه دارم چه بنویسم»   (Gate)

هیچ Repair Actionی حق ندارد خودش تصمیم بگیرد که یک کاندید معتبر است.
Scanner فقط شواهد تولید می‌کند، Validator امتیاز می‌دهد، و Gate با قواعد
سخت اجازه نوشتن می‌دهد یا صریحاً امتناع می‌کند. نبودِ شواهد قوی هرگز به
fallback نرم منجر نمی‌شود؛ به BLOCKED منجر می‌شود.

زنجیره پردازش
-------------
    RawDisk → Scanner → Filesystem Detector → Evidence Builder
            → Evidence Validator → Repair Planner → Hard Safety Gate
            → Patch Transaction → Verify → Commit Journal

سیگنال‌های شواهد (Evidence signals)
-----------------------------------
هر پارتیشن کاندید با این سیگنال‌های مستقل امتیاز می‌گیرد:

    partition_table    ورودی معتبر در جدول پارتیشن (MBR/EBR/GPT)
    vbr_signature      امضای بوت‌سکتور فایل‌سیستم در شروع کاندید
    bpb_consistency    فیلدهای BPB با هم سازگارند (bps/spc/طول/کلاستر)
    mirror_signature   نسخه آینه بوت‌سکتور وجود دارد
    mirror_bpb_match   فیلدهای کلیدی BPB آینه با نسخه اصلی یکی است
    mirror_position    آینه دقیقاً در فاصله مورد انتظار است  ← اثبات طول ولوم
    exfat_checksum     چک‌سام VBR اگزافت (سکتور ۱۱) درست است
    hidden_sectors     BPB_HiddSec برابر LBA شروع پارتیشن است
    partition_offset   PartitionOffset اگزافت برابر LBA شروع است
    refs_superblock    ساختار تکراری ReFS نزدیک انتهای ولوم پیدا شد
    alignment          شروع روی مرز متداول (1MiB یا آفست‌های شناخته‌شده)
    bounds             کاندید کامل داخل محدوده دیسک است

و این blockerها که هر کدام به‌تنهایی نوشتن را رد می‌کنند:

    is_mirror_copy     این کاندید خودش یک نسخه آینه است، نه شروع ولوم
    extent_unverified  طول ولوم از هیچ منبع معتبری اثبات نشده
    out_of_bounds      از انتهای دیسک عبور می‌کند
    overlap            با کاندید دیگری همپوشانی دارد
    encrypted          BitLocker — بدون کلید هیچ ترمیمی معنا ندارد

کلاس‌های مجوز نوشتن (Write Gate)
--------------------------------
    SAFE_RESTORE       منبع، یک ساختار سالمِ موجود روی همین دیسک است.
                       هیچ استنتاجی در کار نیست. مثال: کپی GPT پشتیبانِ
                       دارای CRC معتبر روی GPT اصلی. نیاز: --apply
    INFERRED_REBUILD   ساختار از روی شواهد سنتز می‌شود. نیاز دارد که تمام
                       پارتیشن‌های طرح، شواهد قوی و طول اثبات‌شده داشته
                       باشند و هیچ blocker سراسری فعال نباشد.
                       نیاز: --apply --allow-inferred
    BLOCKED            اجازه نوشتن ندارد. دلیل دقیق چاپ می‌شود.

blockerهای سراسری دیسک (هیچ سنتزی از آنها عبور نمی‌کند)
-------------------------------------------------------
* عدم تطابق هندسه: اندازه واقعی دیسک با مقادیر داخل GPT نمی‌خواند.
  محتمل‌ترین علت در این پروژه، اندازه غلط extent در VMDK اصلاح‌شده است.
  در آن حالت همه آفست‌ها جابه‌جا هستند و هر بازسازی فاجعه است. تنها
  اقدامی که از این blocker عبور می‌کند gpt-fix-geometry است.
* هدف یک کانتینر است (VMDK sparse/descriptor، VHD، VHDX، QCOW2) نه دیسک خام.
* دیسک شامل ولوم سیستمی است.
* همپوشانی پارتیشن‌های کاندید.

--------------------------------------------------------------------------------
هشدارهای حیاتی
--------------------------------------------------------------------------------
* اول ایمیج بگیر: --image-out PATH  (با retry و ثبت badmap).
* اگر دیسک صدای غیرعادی می‌دهد یا SMART خراب است، هیچ ترمیمی نکن.
* ترمیم ساختار، داده را برنمی‌گرداند؛ فقط ساختار را برمی‌گرداند.
* ReFS با مدل NTFS ترمیم نمی‌شود. ReFS آینه بوت‌سکتور ندارد و این ابزار
  عمداً هیچ ترمیم سطح-سکتوری روی ReFS انجام نمی‌دهد؛ فقط شواهد جمع می‌کند
  و به refsutil salvage ویندوز هدایت می‌کند.
* دیسک داینامیک (LDM) یا Storage Spaces: بازسازی جدول، ولوم منطقی را
  برنمی‌گرداند.

--------------------------------------------------------------------------------
نصب و اجرا
--------------------------------------------------------------------------------
نیاز: فقط Python 3.8+ (بدون پکیج خارجی).

ویندوز (Run as Administrator):
    chcp 65001
    python diskdoctor.py --self-test
    python diskdoctor.py --list
    python diskdoctor.py --disk 2 --scan --explain

لینوکس (root):
    sudo python3 diskdoctor.py --disk /dev/sdb --scan

روی ایمیج خام (بدون نیاز به ادمین):
    python3 diskdoctor.py --disk /path/flat.img --scan

--------------------------------------------------------------------------------
شرح کامل سوییچ‌ها
--------------------------------------------------------------------------------
انتخاب هدف:
  --list                 فهرست دیسک‌های سیستم.
  --disk TARGET          شماره دیسک ویندوز (--disk 2)، \\.\PhysicalDrive2،
                         /dev/sdb، یا مسیر فایل ایمیج.
  --sector-size N        اندازه سکتور منطقی (512/4096). پیش‌فرض: از دستگاه.
  --offset BYTES         آفست شروع داخل فایل ایمیج.

triage — تشخیص عمق خرابی (فقط خواندن):
  --triage               برای هر پارتیشن مشکوک: سکتور اول و آنتروپی آن،
                         جستجوی ساختار فایل‌سیستم در انتهای پارتیشن، بازیابی
                         نسخه header ولوم ReFS اگر باشد، نقشه خرابی، پویش
                         مرز، و نتیجه‌گیری با گام بعدی.
  --triage-all           حتی روی پارتیشن‌های سالم هم اجرا کن
  --triage-samples N     تعداد نمونه نقشه خرابی (پیش‌فرض 320)
  --triage-sample-kib N  حجم هر نمونه (پیش‌فرض 64)
  --triage-tail-mib N    چقدر از انتهای پارتیشن گشته شود (پیش‌فرض 512)
  --triage-edge-gib N    سقف پویش ترتیبی برای یافتن اولین ساختار (پیش‌فرض 16)
  --triage-head-gib N    حجم نقشه متراکم ابتدای ولوم (پیش‌فرض 8 گیگابایت)
  --triage-head-samples N  تعداد نمونه نقشه متراکم ابتدا (پیش‌فرض 128)
  --baseline DISK:LBA    ولوم سالم کنترل، مثل 6:32768. بدون کنترل، آنتروپی
                         به‌عنوان شاهد خرابی استفاده نمی‌شود.

  خواندن نقشه خرابی:
    R = ساختار فایل‌سیستم    # = داده بیگانه با آنتروپی بالا
    d = داده معمولی          . = صفر
    - = کم‌آنتروپی           F = فایل‌سیستم دیگر    X = خطای خواندن

اسکن و گزارش:
  --scan                 اسکن و گزارش. فقط خواندن.
  --deep                 اسکن عمیق امضایی برای ولوم‌های گمشده.
  --deep-step BYTES      فیلتر هم‌ترازی کاندیدها. پیش‌فرض 1MiB. با 512 هر
                         سکتور پذیرفته می‌شود (کاندید کاذب بیشتر).
  --deep-limit BYTES     سقف حجم اسکن عمیق. 0 = کل دیسک.
  --deep-ignore-table    محدوده پارتیشن‌های جدول را هم بگرد (وقتی جدول مشکوک است)
  --time-budget SEC      سقف زمان اسکن عمیق.
  --explain              چاپ جدول کامل شواهد هر کاندید با دلیل هر سیگنال.
  --find-name TEXT       جستجوی نام فایل در بایت‌های خام دیسک، مستقل از
                         فایل‌سیستم. UTF-16 و ASCII، بدون حساسیت به حروف.
  --find-limit BYTES     سقف حجم جستجو (0 = کل دیسک)
  --find-name-file PATH  متن --find-name را از فایل بخوان (BOM خودکار حذف)
  --find-max-hits N      سقف تعداد موارد گزارش‌شده (پیش‌فرض 50)
  --dump-range LBA:COUNT استخراج محدوده سکتور خام به فایل + چاپ رشته‌های
                         خوانا. مثل  9211248:64
  --dump-out PATH        مسیر خروجی --dump-range (پیش‌فرض dump.bin)
  --dump-strings-min N   حداقل طول رشته خوانا (پیش‌فرض 6)
  --dump-raw-strings     نمایش همه رشته‌ها بدون فیلتر نویز
  --find-vbm              جستجوی محتوای واقعی .vbm (تگ XML)، نه فقط اسم فایل
  --find-vbm-window N     حجم پنجره خوانده‌شده بعد از هر <BackupMeta> (512KiB)
  --find-vbm-max-hits N   سقف تعداد .vbm گزارش‌شده (پیش‌فرض 20)
  --carve-vbk CENTER:GIB  استخراج محدوده بزرگ اطراف یک LBA شناخته‌شده
  --carve-out PATH        مسیر خروجی --carve-vbk (پیش‌فرض carved.bin)
  --locate-vbk CENTER:SIZE  یافتن نقطه شروع دقیق با اندازه دقیق + تراز بلوک
  --locate-align N         تراز جستجو به بایت (پیش‌فرض 65536)
  --locate-radius-gib N    شعاع جستجو حول center به گیگابایت (پیش‌فرض 2)
  --locate-verify TEXT     تایید کاندیدهای برتر با جستجوی این متن در محتوای
                          واقعی — لازم روی repository پرتراکم
  --locate-verify-top-n N  چند کاندید برتر تایید شود (پیش‌فرض 40)
  --locate-probe-mib N     حجم پروب محتوا به مگابایت (پیش‌فرض 8)
  --json PATH            گزارش ساختاریافته JSON (شامل کل شواهد).

ترمیم:
  --plan                 فقط طرح‌های پیشنهادی و کلاس مجوز هر کدام.
  --wizard               حالت تعاملی با امکان بازگشت (b) در هر پرسش.
  --action ACTION        اجرای یک اقدام. بدون --apply فقط پیش‌نمایش.
  --part N               شماره پارتیشن هدف (همان ستون # در گزارش همین اجرا).
  --letter X             حرف درایو برای chkdsk/refsutil.

اقدام‌ها:
  gpt-restore-primary    آرایه ورودی‌های GPT پشتیبان بایت‌به‌بایت روی GPT اصلی
                         کپی می‌شود. هدر پشتیبان عیناً کپی و فقط MyLBA،
                         AlternateLBA، PartitionEntryLBA و CRC هدر عوض
                         می‌شوند. entry_size، revision، reserved و بقیه
                         متادیتا دست‌نخورده می‌ماند.        [SAFE_RESTORE]
  gpt-restore-backup     همان کار در جهت عکس.               [SAFE_RESTORE]
  gpt-fix-crc            فقط دو فیلد CRC هدر (آفست 16 و 88) روی بایت‌های
                         موجود دیسک اصلاح می‌شود. اگر خود آرایه ورودی‌ها
                         خراب باشد، امتناع می‌کند.          [SAFE_RESTORE]
  gpt-fix-geometry       اصلاح AlternateLBA و LastUsableLBA با اندازه واقعی
                         دیسک. تنها اقدامی که از blocker هندسه عبور می‌کند.
  mbr-write-protective   نوشتن Protective MBR وقتی GPT سالم است.
                                                            [SAFE_RESTORE]
  mbr-rebuild            ساخت جدول MBR از کاندیدها.      [INFERRED_REBUILD]
  gpt-rebuild            ساخت کامل GPT از کاندیدها.      [INFERRED_REBUILD]
  vbr-restore            کپی آینه بوت‌سکتور روی نسخه اصلی. فقط وقتی
                         mirror_bpb_match و mirror_position هر دو تایید
                         شده باشند.                          [SAFE_RESTORE]
  vbr-restore-reverse    جهت عکس: نسخه اصلی سالم، آینه خراب.
  parttype-fix           اصلاح Type ID / Type GUID طبق فایل‌سیستم واقعی.
  refsutil               اجرای refsutil salvage با سینتکس صحیح ویندوز.
  chkdsk                 اجرای chkdsk /f روی حرف درایو.
  rescan                 وادار کردن ویندوز به بازخوانی جدول.

ایمنی:
  --apply                اجازه نوشتن. بدون آن هیچ بایتی نوشته نمی‌شود.
  --allow-inferred       اجازه اضافه و صریح برای اقدام‌های INFERRED_REBUILD.
                         --apply به‌تنهایی برای سنتز ساختار کافی نیست.
  --yes                  رد شدن از تایید تایپی (برای اسکریپت).
  --force                منسوخ؛ هیچ محافظ نوشتن یا تأییدی را دور نمی‌زند.
  --offline              برای سازگاری نگه داشته شده؛ کنترل حالت دیسک هنگام
                         نوشتن اجباری است و حالت اصلی پس از تأیید بازمی‌گردد.
  --backup-dir DIR       محل Journal و بکاپ ساختارها.
                         پیش‌فرض: ./diskdoctor_backups

Journal و بازگشت:
  --undo JOURNAL.json    برگرداندن بایت‌به‌بایت. Journalهای نیمه‌کاره
                         (وضعیت partial بعد از crash) هم پشتیبانی می‌شوند:
                         فقط patchهایی که واقعاً نوشته شده‌اند برمی‌گردند.
  --inspect JOURNAL.json نمایش وضعیت هر patch یک Journal بدون تغییر دیسک.
  --check-journals       جستجوی Journalهای ناتمام در backup-dir و هشدار.

ایمیج‌گیری فارنزیک:
  --image-out PATH       ایمیج خام. خطای خواندن silently صفر نمی‌شود:
                         chunk → retry → بازیابی سکتوربه‌سکتور → badmap.
  --image-retries N      تعداد تلاش مجدد هر سکتور. پیش‌فرض 3.
  --image-fill zero|pat  پرکننده سکتور غیرقابل‌خواندن. pat یک الگوی قابل
                         تشخیص می‌نویسد تا با داده واقعی اشتباه نشود.
  --image-limit BYTES    محدود کردن حجم ایمیج.
  فایل PATH.badmap.json محدوده‌های خوانده‌نشده را دقیقاً ثبت می‌کند.

سایر:
  --refs-out DIR         مسیر خروجی refsutil salvage.
  --refs-work DIR        مسیر working directory برای refsutil.
  --log PATH             فایل لاگ.
  --lang fa|en           زبان رابط.
  --no-color --quiet --verbose
  --self-test            تست داخلی روی ایمیج‌های ساختگی.
  --help-full            چاپ همین راهنما.

--------------------------------------------------------------------------------
جریان کاری پیشنهادی
--------------------------------------------------------------------------------
  کوتاه‌ترین مسیر (اگر وقت نداری، فقط همین):
      python diskdoctor.py --auto --all
  یک فایل گزارش می‌سازد که همه‌چیز در آن است. اگر لازم شد همان یک فایل را
  بفرست. هیچ چیزی نوشته نمی‌شود، پس اجرایش بی‌خطر است.

  مسیر کامل:
  1. python diskdoctor.py --self-test
  2. python diskdoctor.py --list
  3. python diskdoctor.py --disk 2 --scan --explain --triage --json rep.json
     این یک دستور همه چیز را می‌گوید: ساختار، شواهد، عمق خرابی، گام بعدی.
  4. اگر ولوم گمشده‌ای هست:  --scan --deep --explain
     اگر جدول پارتیشن مشکوک است:  --scan --deep --deep-ignore-table
  5. python diskdoctor.py --disk 2 --image-out D:\img\d2.img
  6. اقدام SAFE_RESTORE:
       python diskdoctor.py --disk 2 --action gpt-restore-primary
       python diskdoctor.py --disk 2 --action gpt-restore-primary --apply
     اقدام INFERRED_REBUILD:
       python diskdoctor.py --disk 2 --deep --action gpt-rebuild
       python diskdoctor.py --disk 2 --deep --action gpt-rebuild --apply --allow-inferred
  7. برگشت:  python diskdoctor.py --undo diskdoctor_backups\journal_XXXX.json

کدهای خروج
----------
  0 موفق   1 خطا   2 پارامتر   3 دسترسی   4 هدف نیست   5 لغو
  6 تست شکست خورد   7 نوشتن توسط Gate رد شد
================================================================================
"""

import argparse
import base64
import binascii
import ctypes
import datetime
import hashlib
import json
import math
import os
import re
import struct
import subprocess
import sys
import tempfile
import time
import uuid

import diskdoctor_core as core
import diskdoctor_safety as safety
import diskdoctor_imaging as imaging

VERSION = "2.0.0-rc1"
IS_WIN = (os.name == "nt")
IS_LINUX = sys.platform.startswith("linux")

KIB = 1024
MIB = 1024 * 1024
GIB = 1024 * 1024 * 1024
TIB = 1024 ** 4

DEFAULT_SECTOR = 512
GPT_SIG = b"EFI PART"
GPT_HEADER_SIZE = 92
GPT_ENTRY_SIZE = 128
GPT_ENTRY_COUNT = 128

EXIT_OK = 0
EXIT_ERR = 1
EXIT_ARG = 2
EXIT_PERM = 3
EXIT_NOTFOUND = 4
EXIT_CANCEL = 5
EXIT_TESTFAIL = 6
EXIT_BLOCKED = 7

# Write-gate classes
GATE_SAFE = "SAFE_RESTORE"
GATE_INFERRED = "INFERRED_REBUILD"
GATE_BLOCKED = "BLOCKED"

MSGS = {
    "fa": {
        "need_admin": "دسترسی کافی نیست. ویندوز: Run as Administrator. لینوکس: sudo.",
        "target_open_fail": "باز کردن هدف ممکن نشد",
        "readonly_note": "حالت فقط-خواندن. برای نوشتن از --apply استفاده کن.",
        "no_write_wo_apply": "بدون --apply هیچ نوشتنی انجام نمی‌شود.",
        "confirm_type": "برای ادامه دقیقاً بنویس YES و Enter بزن: ",
        "cancelled": "لغو شد.",
        "scheme": "طرح پارتیشن‌بندی",
        "parts_found": "پارتیشن‌های شناسایی‌شده",
        "no_parts": "هیچ پارتیشنی شناسایی نشد.",
        "warn_header": "هشدارها",
        "blockers": "blockerهای سراسری دیسک",
        "plan_header": "طرح‌های ترمیم پیشنهادی",
        "no_plan": "طرح ترمیم خودکاری پیشنهاد نمی‌شود.",
        "back_hint": "b=بازگشت  q=خروج  ?=راهنما",
        "applied": "اعمال شد",
        "journal_saved": "Journal ذخیره شد",
        "undo_done": "بازگردانی کامل شد",
        "dryrun": "پیش‌نمایش (بدون نوشتن)",
        "sys_disk_block": "این دیسک شامل ولوم سیستمی است. نوشتن مطلقاً مسدود است.",
        "need_inferred": "این اقدام ساختار را سنتز می‌کند. علاوه بر --apply به "
                         "--allow-inferred هم نیاز دارد.",
        "evidence": "شواهد",
    },
    "en": {
        "need_admin": "Insufficient privileges. Windows: Run as Administrator. Linux: sudo.",
        "target_open_fail": "Cannot open target",
        "readonly_note": "Read-only mode. Use --apply to write.",
        "no_write_wo_apply": "Nothing is written without --apply.",
        "confirm_type": "Type exactly YES and press Enter to continue: ",
        "cancelled": "Cancelled.",
        "scheme": "Partition scheme",
        "parts_found": "Detected partitions",
        "no_parts": "No partitions detected.",
        "warn_header": "Warnings",
        "blockers": "Disk-level blockers",
        "plan_header": "Suggested repair plans",
        "no_plan": "No automatic repair plan suggested.",
        "back_hint": "b=back  q=quit  ?=help",
        "applied": "applied",
        "journal_saved": "Journal saved",
        "undo_done": "Undo complete",
        "dryrun": "Preview (no write)",
        "sys_disk_block": "BLOCKED_SYSTEM_DISK: raw mutation is absolutely forbidden.",
        "need_inferred": "This action synthesises structure. It needs --allow-inferred "
                         "in addition to --apply.",
        "evidence": "Evidence",
    },
}
LANG = "fa"


def T(key):
    return MSGS.get(LANG, MSGS["en"]).get(key, MSGS["en"].get(key, key))


class C:
    enabled = True
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GREY = "\033[90m"

    @classmethod
    def w(cls, code, s):
        return s if not cls.enabled else code + s + cls.RESET


QUIET = False
VERBOSE = False
EXPLAIN = False
LOGFILE = None
REPORTFILE = None
_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def _strip_ansi(s):
    return _ANSI_RE.sub("", str(s))


def _log(s):
    if REPORTFILE:
        try:
            REPORTFILE.write(_strip_ansi(s) + "\n")
        except Exception:
            pass
    if LOGFILE:
        try:
            LOGFILE.write("%s %s\n" % (
                datetime.datetime.now().strftime("%H:%M:%S"), _strip_ansi(s)))
            LOGFILE.flush()
        except Exception:
            pass


def out(s=""):
    if not QUIET:
        print(s)
    _log(s)


def info(s):
    out(C.w(C.CYAN, "[i] ") + s)


def ok(s):
    out(C.w(C.GREEN, "[+] ") + s)


def warn(s):
    out(C.w(C.YELLOW, "[!] ") + s)


def err(s):
    print(C.w(C.RED, "[x] ") + s, file=sys.stderr)
    _log("[x] " + s)


def dbg(s):
    if VERBOSE:
        out(C.w(C.GREY, "[d] " + s))


def enable_win_vt():
    if not IS_WIN:
        return
    try:
        k = ctypes.windll.kernel32
        k.GetStdHandle.restype = ctypes.c_void_p
        h = ctypes.c_void_p(k.GetStdHandle(-11))
        mode = ctypes.c_uint32()
        if k.GetConsoleMode(h, ctypes.byref(mode)):
            k.SetConsoleMode(h, mode.value | 0x0004)
    except Exception:
        pass


def setup_stdio():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    enable_win_vt()


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def human(n):
    if n is None:
        return "?"
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(n) < 1024.0 or unit == "PiB":
            return ("%d B" % int(n)) if unit == "B" else ("%.2f %s" % (n, unit))
        n /= 1024.0
    return "%.2f PiB" % n


def crc32(b):
    return binascii.crc32(b) & 0xFFFFFFFF


def guid_to_str(b):
    if len(b) != 16:
        return ""
    return "%08X-%04X-%04X-%s-%s" % (
        struct.unpack_from("<I", b, 0)[0], struct.unpack_from("<H", b, 4)[0],
        struct.unpack_from("<H", b, 6)[0], b[8:10].hex().upper(),
        b[10:16].hex().upper())


def str_to_guid(s):
    h = s.replace("-", "").replace("{", "").replace("}", "")
    if len(h) != 32:
        raise ValueError("bad guid: %r" % s)
    raw = bytes.fromhex(h)
    return (struct.pack("<I", struct.unpack(">I", raw[0:4])[0]) +
            struct.pack("<H", struct.unpack(">H", raw[4:6])[0]) +
            struct.pack("<H", struct.unpack(">H", raw[6:8])[0]) + raw[8:16])


def new_guid():
    return str_to_guid(str(uuid.uuid4()).upper())


ZERO_GUID = b"\x00" * 16


def hexdump(data, base=0, limit=256):
    lines = []
    data = data[:limit]
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        lines.append("%08X  %-47s  |%s|" % (
            base + i, " ".join("%02x" % c for c in chunk),
            "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)))
    return "\n".join(lines)


def hexdiff(old, new, base=0, max_rows=24):
    rows = []
    n = max(len(old or b""), len(new))
    old = (old or b"").ljust(n, b"\x00")
    new = new.ljust(n, b"\x00")
    shown = 0
    for i in range(0, n, 16):
        a, b = old[i:i + 16], new[i:i + 16]
        if a == b:
            continue
        if shown >= max_rows:
            rows.append("     ... %d more changed rows" % ((n - i) // 16))
            break
        rows.append(C.w(C.RED, "   - " + hexdump(a, base + i, 16)))
        rows.append(C.w(C.GREEN, "   + " + hexdump(b, base + i, 16)))
        shown += 1
    return "\n".join(rows) if rows else "     (identical)"


def is_admin():
    if IS_WIN:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return True


def run_cmd(args, timeout=120):
    try:
        p = subprocess.run(args, capture_output=True, timeout=timeout,
                           shell=isinstance(args, str))
        dec = lambda b: b.decode("utf-8", "replace") if isinstance(b, bytes) else str(b)
        return p.returncode, dec(p.stdout), dec(p.stderr)
    except FileNotFoundError:
        return 127, "", "not found: %r" % (args,)
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", str(e)


def ps(script, timeout=120):
    return run_cmd(["powershell", "-NoProfile", "-NonInteractive",
                    "-ExecutionPolicy", "Bypass", "-Command", script], timeout)


# =============================================================================
# SECTION 2 — Raw device access layer  (RawDisk)
# =============================================================================
# On Windows, \\.\PhysicalDriveN requires SECTOR-ALIGNED reads and writes.
# Python's buffered IO issues arbitrary-size reads, so we always open with
# buffering=0 and align every access ourselves.
# =============================================================================

class DiskError(Exception):
    pass


class RawDisk(object):
    def __init__(self, path, sector_size=None, base_offset=0, writable=False):
        self.path = path
        self.base = int(base_offset or 0)
        self.writable = writable
        self.is_device = False
        self.win_index = None
        self.fh = None
        self.size = 0
        self.sector = sector_size or DEFAULT_SECTOR
        self._explicit_sector = sector_size is not None
        self._write_authorized = False
        self._open()
        safety.attach_identity(sys.modules[__name__], self)

    # -- lifecycle ---------------------------------------------------------
    def _open(self):
        p = self.path
        mode = "rb+" if self.writable else "rb"
        if IS_WIN and re.match(r"^\\\\[.?]\\PhysicalDrive\d+$", p, re.I):
            self.is_device = True
            m = re.search(r"(\d+)$", p)
            self.win_index = int(m.group(1))
        elif not IS_WIN and p.startswith("/dev/"):
            self.is_device = True
        try:
            self.fh = open(p, mode, buffering=0)
        except PermissionError:
            raise DiskError("%s: %s (%s)" % (T("target_open_fail"), p, T("need_admin")))
        except FileNotFoundError:
            raise DiskError("%s: %s" % (T("target_open_fail"), p))
        except OSError as e:
            raise DiskError("%s: %s (%s)" % (T("target_open_fail"), p, e))
        self._probe_geometry()

    def close(self):
        if self.fh:
            try:
                self.fh.close()
            except Exception:
                pass
            self.fh = None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    # -- geometry ----------------------------------------------------------
    def _probe_geometry(self):
        size = 0
        sec = self.sector
        if self.is_device and IS_WIN:
            size, sec2 = self._win_geometry()
            if sec2 and not self._explicit_sector:
                sec = sec2
        elif self.is_device and IS_LINUX:
            size, sec2 = self._linux_geometry()
            if sec2 and not self._explicit_sector:
                sec = sec2
        if not size:
            try:
                size = os.path.getsize(self.path)
            except OSError:
                size = 0
        if not size:
            try:
                cur = self.fh.seek(0, os.SEEK_END)
                size = cur
                self.fh.seek(0)
            except Exception:
                size = 0
        self.sector = sec or DEFAULT_SECTOR
        self.size = max(0, size - self.base)
        if self.size == 0:
            raise DiskError("size of %s is zero / unreadable" % self.path)

    def _win_geometry(self):
        """IOCTL_DISK_GET_LENGTH_INFO + IOCTL_DISK_GET_DRIVE_GEOMETRY."""
        try:
            k = ctypes.windll.kernel32
            handle = ctypes.c_void_p(msvcrt_get_osfhandle(self.fh.fileno()))
            IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C
            IOCTL_DISK_GET_DRIVE_GEOMETRY = 0x00070000
            buf = ctypes.create_string_buffer(8)
            ret = ctypes.c_uint32()
            size = 0
            if k.DeviceIoControl(handle, IOCTL_DISK_GET_LENGTH_INFO, None, 0,
                                 buf, 8, ctypes.byref(ret), None):
                size = struct.unpack("<q", buf.raw[:8])[0]
            gbuf = ctypes.create_string_buffer(24)
            sec = 0
            if k.DeviceIoControl(handle, IOCTL_DISK_GET_DRIVE_GEOMETRY, None, 0,
                                 gbuf, 24, ctypes.byref(ret), None):
                sec = struct.unpack_from("<I", gbuf.raw, 20)[0]
            return size, sec
        except Exception as e:
            dbg("win geometry failed: %s" % e)
            return 0, 0

    def _linux_geometry(self):
        try:
            import fcntl
            BLKGETSIZE64 = 0x80081272
            BLKSSZGET = 0x1268
            b = ctypes.create_string_buffer(8)
            fcntl.ioctl(self.fh.fileno(), BLKGETSIZE64, b)
            size = struct.unpack("<Q", b.raw)[0]
            b2 = ctypes.create_string_buffer(4)
            fcntl.ioctl(self.fh.fileno(), BLKSSZGET, b2)
            sec = struct.unpack("<I", b2.raw)[0]
            return size, sec
        except Exception as e:
            dbg("linux geometry failed: %s" % e)
            return 0, 0

    # -- io ----------------------------------------------------------------
    @property
    def sectors(self):
        return self.size // self.sector

    def read_at(self, offset, length):
        """Aligned-safe read. offset/length in bytes, relative to base."""
        if length <= 0:
            return b""
        if offset < 0:
            raise DiskError("negative offset")
        s = self.sector
        abs_off = self.base + offset
        start = (abs_off // s) * s
        end = ((abs_off + length + s - 1) // s) * s
        maxend = self.base + self.size
        if end > maxend:
            end = ((maxend + s - 1) // s) * s
        if start >= maxend:
            return b""
        try:
            self.fh.seek(start)
            raw = self.fh.read(end - start)
        except OSError as e:
            raise DiskError("read error @%d (%s)" % (start, e))
        if raw is None:
            return b""
        skip = abs_off - start
        return raw[skip:skip + length]

    def read_lba(self, lba, count=1):
        return self.read_at(lba * self.sector, count * self.sector)

    def write_at(self, offset, data):
        """Exact bounded aligned RMW; only a controlled transaction may write."""
        if not self.writable or not self._write_authorized:
            raise DiskError("raw mutation requires a v2 transaction capability")
        if offset < 0 or offset + len(data) > self.size:
            raise DiskError("write range outside source")
        if not data:
            return 0
        sector = self.sector
        absolute = self.base + offset
        first = absolute // sector * sector
        end = ((absolute + len(data) + sector - 1) // sector) * sector
        if end > self.base + self.size:
            if self.is_device:
                raise DiskError("aligned write extends beyond source")
            end = self.base + self.size
        self.fh.seek(first)
        block = bytearray(self.fh.read(end - first))
        if len(block) != end - first:
            raise DiskError("short read before aligned write")
        skip = absolute - first
        block[skip:skip + len(data)] = data
        self.fh.seek(first)
        written = self.fh.write(bytes(block))
        if written != len(block):
            raise core.SafetyError("FAILED_WRITE", "short source write")
        try:
            self.fh.flush()
            os.fsync(self.fh.fileno())
        except OSError as e:
            raise core.SafetyError("FAILED_DURABILITY", str(e)) from e
        return len(data)

    def write_lba(self, lba, data):
        return self.write_at(lba * self.sector, data)

    def reopen(self, writable):
        self.close()
        self.writable = writable
        self._open()


def msvcrt_get_osfhandle(fd):
    import msvcrt
    return msvcrt.get_osfhandle(fd)


# =============================================================================
# SECTION 3 — Disk enumeration
# =============================================================================

def list_disks():
    """Return a list of dicts describing attached disks."""
    if IS_WIN:
        d = _list_disks_win_ps()
        if d:
            return d
        return _list_disks_win_wmic()
    if IS_LINUX:
        return _list_disks_linux()
    return []


def _list_disks_win_ps():
    rc, so, se = ps(
        "Get-Disk | Select-Object Number,FriendlyName,SerialNumber,Size,"
        "PartitionStyle,OperationalStatus,IsOffline,IsReadOnly,BusType,"
        "LogicalSectorSize | ConvertTo-Json -Compress")
    if rc != 0 or not so.strip():
        return []
    try:
        data = json.loads(so)
    except Exception:
        return []
    if isinstance(data, dict):
        data = [data]
    disks = []
    for d in data:
        disks.append({
            "index": d.get("Number"),
            "path": r"\\.\PhysicalDrive%s" % d.get("Number"),
            "model": (d.get("FriendlyName") or "").strip(),
            "serial": (d.get("SerialNumber") or "").strip(),
            "size": int(d.get("Size") or 0),
            "style": d.get("PartitionStyle"),
            "status": d.get("OperationalStatus"),
            "offline": bool(d.get("IsOffline")),
            "readonly": bool(d.get("IsReadOnly")),
            "bus": d.get("BusType"),
            "sector": int(d.get("LogicalSectorSize") or 0) or None,
        })
    for d in disks:
        d["volumes"] = _win_disk_volumes(d["index"])
    return disks


def _list_disks_win_wmic():
    rc, so, se = run_cmd(["wmic", "diskdrive", "get",
                          "Index,Model,SerialNumber,Size,BytesPerSector", "/format:csv"])
    disks = []
    if rc != 0:
        return disks
    for line in so.splitlines():
        parts = [x.strip() for x in line.split(",")]
        if len(parts) < 6 or parts[1] in ("BytesPerSector", ""):
            continue
        try:
            disks.append({
                "index": int(parts[2]),
                "path": r"\\.\PhysicalDrive%s" % parts[2],
                "sector": int(parts[1] or 512),
                "model": parts[3],
                "serial": parts[4],
                "size": int(parts[5] or 0),
                "style": None, "status": None, "offline": None,
                "readonly": None, "bus": None, "volumes": [],
            })
        except Exception:
            continue
    return disks


def _win_disk_volumes(index):
    """Map a physical disk number to its partitions/volumes/drive letters."""
    if index is None:
        return []
    rc, so, se = ps(
        "Get-Partition -DiskNumber %d -ErrorAction SilentlyContinue | "
        "ForEach-Object { $v = Get-Volume -Partition $_ -ErrorAction SilentlyContinue; "
        "[PSCustomObject]@{ Num=$_.PartitionNumber; Offset=$_.Offset; Size=$_.Size; "
        "Letter=$_.DriveLetter; Type=$_.Type; GptType=$_.GptType; MbrType=$_.MbrType; "
        "FS=$v.FileSystem; Label=$v.FileSystemLabel } } | ConvertTo-Json -Compress" % index)
    if rc != 0 or not so.strip():
        return []
    try:
        data = json.loads(so)
    except Exception:
        return []
    if isinstance(data, dict):
        data = [data]
    return data


def _list_disks_linux():
    rc, so, se = run_cmd(["lsblk", "-J", "-b", "-d", "-o",
                          "NAME,PATH,SIZE,MODEL,SERIAL,RO,TYPE,PTTYPE,LOG-SEC"])
    disks = []
    if rc != 0:
        return disks
    try:
        data = json.loads(so)
    except Exception:
        return disks
    for i, d in enumerate(data.get("blockdevices", [])):
        if d.get("type") not in ("disk", "loop"):
            continue
        disks.append({
            "index": i,
            "path": d.get("path"),
            "model": (d.get("model") or "").strip(),
            "serial": (d.get("serial") or "").strip(),
            "size": int(d.get("size") or 0),
            "style": d.get("pttype"),
            "status": None,
            "offline": False,
            "readonly": bool(d.get("ro")),
            "bus": None,
            "sector": int(d.get("log-sec") or 512),
            "volumes": [],
        })
    return disks


def resolve_target(spec):
    """--disk value -> concrete path."""
    if spec is None:
        return None
    spec = str(spec)
    if re.fullmatch(r"\d+", spec):
        if IS_WIN:
            return r"\\.\PhysicalDrive%s" % spec
        disks = list_disks()
        for d in disks:
            if str(d["index"]) == spec:
                return d["path"]
        raise DiskError("disk index %s not found" % spec)
    return spec


def system_disk_indices():
    """Indices of disks that host the running OS (write-protected by default)."""
    idx = set()
    if IS_WIN:
        rc, so, _ = ps(
            "$sys = (Get-Item Env:SystemDrive).Value.TrimEnd(':'); "
            "Get-Partition -DriveLetter $sys -ErrorAction SilentlyContinue | "
            "Select-Object -ExpandProperty DiskNumber")
        if rc == 0:
            for line in so.split():
                if line.strip().isdigit():
                    idx.add(int(line.strip()))
    elif IS_LINUX:
        rc, so, _ = run_cmd(["findmnt", "-n", "-o", "SOURCE", "/"])
        if rc == 0 and so.strip():
            src = so.strip()
            m = re.match(r"(/dev/[a-z]+|/dev/nvme\d+n\d+)", src)
            if m:
                idx.add(m.group(1))
    return idx


# =============================================================================

# =============================================================================
# SECTION 4 — Partition type tables
# =============================================================================

MBR_TYPES = {
    0x00: "Empty", 0x01: "FAT12", 0x04: "FAT16 <32M", 0x05: "Extended (CHS)",
    0x06: "FAT16B", 0x07: "NTFS/exFAT/ReFS/HPFS", 0x0B: "FAT32 (CHS)",
    0x0C: "FAT32 (LBA)", 0x0E: "FAT16 (LBA)", 0x0F: "Extended (LBA)",
    0x11: "Hidden FAT12", 0x14: "Hidden FAT16<32M", 0x16: "Hidden FAT16B",
    0x17: "Hidden NTFS", 0x1B: "Hidden FAT32", 0x1C: "Hidden FAT32 (LBA)",
    0x1E: "Hidden FAT16 (LBA)", 0x27: "Windows RE (hidden NTFS)",
    0x39: "Plan 9", 0x3C: "PartitionMagic", 0x42: "Windows LDM (dynamic)",
    0x82: "Linux swap / Solaris", 0x83: "Linux", 0x85: "Linux extended",
    0x8E: "Linux LVM", 0xA0: "Hibernation", 0xA5: "FreeBSD", 0xA6: "OpenBSD",
    0xA8: "macOS UFS", 0xAB: "macOS boot", 0xAF: "HFS/HFS+",
    0xBE: "Solaris boot", 0xBF: "Solaris", 0xEB: "BeFS",
    0xEE: "GPT protective", 0xEF: "EFI System (FAT)",
    0xFB: "VMware VMFS", 0xFC: "VMware swap", 0xFD: "Linux RAID auto",
}
MBR_EXTENDED = (0x05, 0x0F, 0x85, 0xC5, 0xD5)

GPT_TYPES = {
    "00000000-0000-0000-0000-000000000000": "Unused",
    "C12A7328-F81F-11D2-BA4B-00A0C93EC93B": "EFI System Partition",
    "E3C9E316-0B5C-4DB8-817D-F92DF00215AE": "Microsoft Reserved (MSR)",
    "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7": "Microsoft Basic Data",
    "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC": "Windows Recovery",
    "5808C8AA-7E8F-42E0-85D2-E1E90434CFB3": "Windows LDM metadata",
    "AF9B60A0-1431-4F62-BC68-3311714A69AD": "Windows LDM data",
    "E75CAF8F-F680-4CEE-AFA3-B001E56EFC2D": "Storage Spaces",
    "21686148-6449-6E6F-744E-656564454649": "BIOS boot",
    "0FC63DAF-8483-4772-8E79-3D69D8477DE4": "Linux filesystem",
    "E6D6D379-F507-44C2-A23C-238F2A3DF928": "Linux LVM",
    "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F": "Linux swap",
    "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709": "Linux root (x86-64)",
    "A19D880F-05FC-4D3B-A006-743F0F84911E": "Linux RAID",
    "516E7CB4-6ECF-11D6-8FF8-00022D09712B": "FreeBSD data",
    "48465300-0000-11AA-AA11-00306543ECAC": "Apple HFS+",
    "7C3457EF-0000-11AA-AA11-00306543ECAC": "Apple APFS",
    "6A898CC3-1DD2-11B2-99A6-080020736631": "Solaris/ZFS usr",
    "AA31E02A-400F-11DB-9590-000C2911D1B8": "VMware VMFS",
    "9D275380-40AD-11DB-BF97-000C2911D1B8": "VMware Diagnostic",
    "9198EFFC-31C0-11DB-8F78-000C2911D1B8": "VMware vSAN",
}
GUID_MSDATA = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
GUID_ESP = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
GUID_MSR = "E3C9E316-0B5C-4DB8-817D-F92DF00215AE"
GUID_LINUX = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"
GUID_WINRE = "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC"

# Partition types that are SUPPOSED to be empty. Flagging them as damaged RAW
# volumes and offering to "repair" them is wrong.
NO_FS_GPT_TYPES = {
    "E3C9E316-0B5C-4DB8-817D-F92DF00215AE",   # Microsoft Reserved (MSR)
    "21686148-6449-6E6F-744E-656564454649",   # BIOS boot
    "5808C8AA-7E8F-42E0-85D2-E1E90434CFB3",   # LDM metadata
    "E75CAF8F-F680-4CEE-AFA3-B001E56EFC2D",   # Storage Spaces
    "9D275380-40AD-11DB-BF97-000C2911D1B8",   # VMware Diagnostic
}
NO_FS_MBR_TYPES = {0xEE, 0x12}


def type_expects_no_fs(p):
    t = str(p.type_id or "").upper()
    if t in NO_FS_GPT_TYPES:
        return True
    try:
        return int(t, 16) in NO_FS_MBR_TYPES
    except Exception:
        return False

# Windows-family filesystems whose partition entry must be Microsoft Basic Data
WIN_FS = ("NTFS", "ReFS", "exFAT", "FAT32", "FAT16", "FAT12", "BitLocker")
LINUX_FS = ("ext2/3/4", "XFS", "Btrfs", "Linux swap", "LVM2 PV")


# =============================================================================


# =============================================================================
# SECTION 5 — Filesystem detector
# =============================================================================
# probe_fs() only says "this looks like X and here are its raw BPB fields".
# It deliberately does NOT decide whether a candidate is trustworthy — that is
# the Evidence Builder's job (SECTION 8).
# =============================================================================

WIN_FS = ("NTFS", "ReFS", "exFAT", "FAT32", "FAT16", "FAT12", "BitLocker")
FAT_FS = ("FAT32", "FAT16", "FAT12")

# in-volume backup boot sector location, in sectors from the volume start
#   NTFS  : last sector of the volume  = value of the TotalSectors BPB field
#   FAT32 : BPB_BkBootSec, a WORD at offset 0x32 (NOT 0x34 — that is a
#           reserved byte; getting this wrong is a real, silent bug)
#   exFAT : sectors 12..23 mirror sectors 0..11
#   others: no in-volume mirror exists


def _fs(name, conf, sectors=0, bps=0, mirror=None, fields=None, **detail):
    return {"fs": name, "conf": conf, "sectors": int(sectors), "bps": int(bps),
            "mirror": mirror, "fields": fields or {}, "detail": detail}


def probe_fs(buf, sector_size=512):
    """Identify a filesystem from the first bytes of a candidate volume."""
    if not buf or len(buf) < 512:
        return None
    b = buf

    # ---- NTFS -------------------------------------------------------------
    if b[3:11] == b"NTFS    ":
        f = ntfs_fields(b)
        conf = 0.99 if ntfs_fields_sane(f) else 0.5
        return _fs("NTFS", conf, sectors=f["total_sectors"] + 1 if conf > 0.9 else 0,
                   bps=f["bps"] or sector_size, mirror=f["total_sectors"] or None,
                   fields=f, serial="%016X" % f["serial"])

    # ---- ReFS -------------------------------------------------------------
    if b[3:7] == b"ReFS":
        idx = b.find(b"FSRS", 8, 0x20)
        if idx > 0:
            nsec = u64(b, idx + 8)
            bps = u32(b, idx + 16)
            spc = u32(b, idx + 20)
            major, minor = b[idx + 24], b[idx + 25]
            sane = bps in (512, 1024, 2048, 4096) and 0 < nsec < (1 << 48)
            return _fs("ReFS", 0.97 if sane else 0.6,
                       sectors=nsec if sane else 0, bps=bps if sane else sector_size,
                       mirror=None,
                       fields={"bps": bps, "spc": spc, "total_sectors": nsec,
                               "version": "%d.%d" % (major, minor)},
                       version="%d.%d" % (major, minor),
                       note="ReFS has no VBR mirror; sector-level repair is refused")
        return _fs("ReFS", 0.6, mirror=None)

    # ---- exFAT ------------------------------------------------------------
    if b[3:11] == b"EXFAT   ":
        f = exfat_fields(b)
        sane = (f["bps"] in (512, 1024, 2048, 4096) and 0 < f["volume_length"] < (1 << 48))
        return _fs("exFAT", 0.98 if sane else 0.55,
                   sectors=f["volume_length"] if sane else 0,
                   bps=f["bps"] or sector_size, mirror=12, fields=f,
                   serial="%08X" % f["serial"])

    # ---- BitLocker --------------------------------------------------------
    if b[3:11] == b"-FVE-FS-":
        return _fs("BitLocker", 0.99, sectors=0, bps=u16(b, 0x0B) or sector_size,
                   mirror=None, note="encrypted volume; recovery key required")

    # ---- FAT32 ------------------------------------------------------------
    if b[0x52:0x5A] == b"FAT32   " or _looks_like_fat32(b):
        f = fat_fields(b, 32)
        if f["bps"] in (512, 1024, 2048, 4096):
            bk = f["bk_boot_sec"]
            return _fs("FAT32", 0.95 if fat_fields_sane(f) else 0.55,
                       sectors=f["total_sectors"], bps=f["bps"],
                       mirror=(bk if 0 < bk < 64 else None), fields=f,
                       label=f["label"], oem=f["oem"])

    # ---- FAT12/16 ---------------------------------------------------------
    if b[0x36:0x3E] in (b"FAT12   ", b"FAT16   ", b"FAT     "):
        name = b[0x36:0x3E].decode("latin1").strip()
        f = fat_fields(b, 16)
        if f["bps"] in (512, 1024, 2048, 4096):
            return _fs(name if name.startswith("FAT1") else "FAT16",
                       0.93 if fat_fields_sane(f) else 0.55,
                       sectors=f["total_sectors"], bps=f["bps"], mirror=None,
                       fields=f, label=f["label"], oem=f["oem"])

    # ---- ext2/3/4 ---------------------------------------------------------
    if len(b) >= 2048 and u16(b, 1024 + 0x38) == 0xEF53:
        sb = 1024
        blocks = u32(b, sb + 0x04)
        log_bs = u32(b, sb + 0x18)
        bsz = 1024 << (log_bs & 0xFF) if log_bs < 8 else 4096
        kind = "ext4" if u32(b, sb + 0x60) & 0x40 else "ext2/3"
        label = b[sb + 0x78:sb + 0x88].split(b"\x00")[0].decode("latin1")
        return _fs(kind, 0.96, sectors=(blocks * bsz) // sector_size,
                   bps=sector_size, mirror=None,
                   fields={"blocks": blocks, "block_size": bsz},
                   block_size=bsz, label=label)

    # ---- XFS --------------------------------------------------------------
    if b[0:4] == b"XFSB":
        bsz = struct.unpack_from(">I", b, 4)[0]
        dblocks = struct.unpack_from(">Q", b, 8)[0]
        if 512 <= bsz <= 65536:
            return _fs("XFS", 0.96, sectors=(dblocks * bsz) // sector_size,
                       bps=sector_size, mirror=None,
                       fields={"blocks": dblocks, "block_size": bsz})

    # ---- Btrfs ------------------------------------------------------------
    if len(b) > 0x10048 and b[0x10040:0x10048] == b"_BHRfS_M":
        total = u64(b, 0x10000 + 0x70)
        return _fs("Btrfs", 0.96, sectors=total // sector_size, bps=sector_size,
                   mirror=None, fields={"total_bytes": total})

    # ---- misc -------------------------------------------------------------
    if len(b) > 0x1000 and b[0xFF6:0x1000] == b"SWAPSPACE2":
        return _fs("Linux swap", 0.95, mirror=None)
    if b[0:8] == b"LABELONE" or (len(b) > 520 and b[512:520] == b"LABELONE"):
        return _fs("LVM2 PV", 0.9, mirror=None,
                   note="physical volume; logical volumes live inside")
    if len(b) > 0x402 and b[0x400:0x402] in (b"H+", b"HX"):
        return _fs("HFS+", 0.9, mirror=None)
    if len(b) > 0x24 and b[0x20:0x24] == b"NXSB":
        return _fs("APFS", 0.9, mirror=None)
    if len(b) > 0x8006 and b[0x8001:0x8006] == b"CD001":
        return _fs("ISO9660", 0.9, mirror=None)
    if len(b) > 0x100004 and b[0x100000:0x100004] == b"\x0d\xd0\x01\xc0":
        return _fs("VMFS", 0.9, mirror=None)
    if b[510:512] == b"\x55\xAA":
        return _fs("unknown (0x55AA only)", 0.2, mirror=None)
    return None


def _looks_like_fat32(b):
    """FAT32 without the FilSysType string: RootEntCnt=0, FATSz16=0, FATSz32>0."""
    try:
        return (u16(b, 0x11) == 0 and u16(b, 0x16) == 0 and u32(b, 0x24) > 0
                and u16(b, 0x0B) in (512, 1024, 2048, 4096)
                and u32(b, 0x20) > 0 and b[510:512] == b"\x55\xAA")
    except Exception:
        return False


def ntfs_fields(b):
    return {
        "bps": u16(b, 0x0B),
        "spc": b[0x0D],
        "reserved": u16(b, 0x0E),
        "media": b[0x15],
        "sectors_per_track": u16(b, 0x18),
        "heads": u16(b, 0x1A),
        "hidden_sectors": u32(b, 0x1C),
        "total_sectors": u64(b, 0x28),
        "mft_lcn": u64(b, 0x30),
        "mftmirr_lcn": u64(b, 0x38),
        "serial": u64(b, 0x48),
        "boot_sig": b[510:512] == b"\x55\xAA",
    }


def ntfs_fields_sane(f):
    if f["bps"] not in (512, 1024, 2048, 4096):
        return False
    if f["spc"] not in (1, 2, 4, 8, 16, 32, 64, 128):
        return False
    if not (0 < f["total_sectors"] < (1 << 48)):
        return False
    if f["reserved"] != 0:            # NTFS keeps this BPB field zero
        return False
    if f["bps"] * f["spc"] > 2 * MIB:
        return False
    clusters = f["total_sectors"] // f["spc"]
    if not (0 < f["mft_lcn"] < clusters and 0 < f["mftmirr_lcn"] < clusters):
        return False
    return bool(f["boot_sig"])


def exfat_fields(b):
    bps_shift = b[0x6C]
    spc_shift = b[0x6D]
    return {
        "partition_offset": u64(b, 0x40),
        "volume_length": u64(b, 0x48),
        "fat_offset": u32(b, 0x50),
        "fat_length": u32(b, 0x54),
        "cluster_heap_offset": u32(b, 0x58),
        "cluster_count": u32(b, 0x5C),
        "root_cluster": u32(b, 0x60),
        "serial": u32(b, 0x64),
        "fs_revision": u16(b, 0x68),
        "bps": (1 << bps_shift) if 9 <= bps_shift <= 12 else 0,
        "spc_shift": spc_shift,
        "boot_sig": b[510:512] == b"\x55\xAA",
    }


def fat_fields(b, kind):
    f = {
        "oem": b[3:11].decode("latin1").strip(),
        "bps": u16(b, 0x0B),
        "spc": b[0x0D],
        "reserved": u16(b, 0x0E),
        "num_fats": b[0x10],
        "root_entries": u16(b, 0x11),
        "total_sectors16": u16(b, 0x13),
        "media": b[0x15],
        "fat_size16": u16(b, 0x16),
        "hidden_sectors": u32(b, 0x1C),
        "total_sectors32": u32(b, 0x20),
        "boot_sig": b[510:512] == b"\x55\xAA",
    }
    if kind == 32:
        f["fat_size32"] = u32(b, 0x24)
        f["fs_info"] = u16(b, 0x30)         # BPB_FSInfo
        f["bk_boot_sec"] = u16(b, 0x32)     # BPB_BkBootSec  <- correct offset
        f["volume_id"] = u32(b, 0x43)
        f["label"] = b[0x47:0x52].decode("latin1").strip()
    else:
        f["bk_boot_sec"] = 0
        f["volume_id"] = u32(b, 0x27)
        f["label"] = b[0x2B:0x36].decode("latin1").strip()
    f["total_sectors"] = f["total_sectors32"] or f["total_sectors16"]
    return f


def fat_fields_sane(f):
    if f["bps"] not in (512, 1024, 2048, 4096):
        return False
    if f["spc"] not in (1, 2, 4, 8, 16, 32, 64, 128):
        return False
    if f["num_fats"] not in (1, 2):
        return False
    if f["reserved"] == 0:
        return False
    if not (0 < f["total_sectors"] < (1 << 32)):
        return False
    if f["media"] not in (0xF0, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF):
        return False
    return bool(f["boot_sig"])


# --- exFAT VBR checksum -------------------------------------------------------
# The checksum covers sectors 0..10 of the VBR, skipping VolumeFlags (offsets
# 106,107) and PercentInUse (112), and is stored repeated across sector 11.
EXFAT_SKIP = (106, 107, 112)


def exfat_vbr_checksum(data, bps):
    n = 11 * bps
    if len(data) < n:
        return None
    c = 0
    for i in range(n):
        if i in EXFAT_SKIP:
            continue
        c = (((c << 31) & 0xFFFFFFFF) | (c >> 1)) + data[i]
        c &= 0xFFFFFFFF
    return c


def exfat_checksum_ok(disk, start_lba, bps=None):
    """Read sectors 0..11 of an exFAT VBR and verify the stored checksum."""
    bps = bps or disk.sector
    data = disk.read_at(start_lba * disk.sector, 12 * bps)
    if len(data) < 12 * bps:
        return False, "short read"
    calc = exfat_vbr_checksum(data, bps)
    stored = u32(data, 11 * bps)
    # sector 11 must be the 4-byte checksum repeated for the whole sector
    rep = data[11 * bps:12 * bps]
    uniform = rep == (rep[0:4] * (bps // 4))
    if calc != stored:
        return False, "checksum 0x%08X != stored 0x%08X" % (calc, stored)
    if not uniform:
        return False, "checksum sector is not a uniform repeat"
    return True, "0x%08X" % calc


# --- BPB comparison between a VBR and its mirror -----------------------------
NTFS_MATCH_FIELDS = ("bps", "spc", "total_sectors", "mft_lcn", "mftmirr_lcn", "serial")
FAT_MATCH_FIELDS = ("bps", "spc", "num_fats", "total_sectors", "volume_id", "reserved")
EXFAT_MATCH_FIELDS = ("partition_offset", "volume_length", "fat_offset",
                      "cluster_heap_offset", "cluster_count", "serial", "bps")


def bpb_match(fs_name, a, b):
    """Compare the key BPB fields of a VBR and its mirror. Returns (ok, diffs)."""
    if not a or not b:
        return False, ["missing fields"]
    if fs_name == "NTFS":
        keys = NTFS_MATCH_FIELDS
    elif fs_name == "exFAT":
        keys = EXFAT_MATCH_FIELDS
    elif fs_name in FAT_FS:
        keys = FAT_MATCH_FIELDS
    else:
        return False, ["no mirror model for %s" % fs_name]
    diffs = ["%s %r!=%r" % (k, a.get(k), b.get(k)) for k in keys
             if a.get(k) != b.get(k)]
    return (not diffs), diffs


CARVE_SIGS = [
    (b"NTFS    ", 3, "NTFS"),
    (b"ReFS\x00\x00\x00\x00", 3, "ReFS"),
    (b"EXFAT   ", 3, "exFAT"),
    (b"FAT32   ", 0x52, "FAT32"),
    (b"FAT16   ", 0x36, "FAT16"),
    (b"FAT12   ", 0x36, "FAT12"),
    (b"-FVE-FS-", 3, "BitLocker"),
    (b"XFSB", 0, "XFS"),
]

# ReFS keeps duplicated superblock structures near the end of the volume.
# We only use their PRESENCE as corroborating evidence of the volume extent —
# no ReFS structure is ever written by this tool.
REFS_SUPERBLOCK_SIG = b"SUPB"
REFS_CHECKPOINT_SIG = b"CHKP"
# SECTION 6 — MBR parser/builder
# =============================================================================

class MbrEntry(object):
    __slots__ = ("boot", "type", "start", "sectors", "raw", "slot", "src")

    def __init__(self, raw, slot=0, base=0, src="MBR"):
        self.raw = raw
        self.slot = slot
        self.src = src
        self.boot = raw[0]
        self.type = raw[4]
        self.start = u32(raw, 8) + base
        self.sectors = u32(raw, 12)

    @property
    def empty(self):
        return self.type == 0x00 or self.sectors == 0

    @property
    def end(self):
        return self.start + self.sectors - 1

    def type_name(self):
        return MBR_TYPES.get(self.type, "0x%02X (unknown)" % self.type)


def build_mbr_entry(part_type, start_lba, sectors, bootable=False):
    """16-byte MBR entry. CHS fields are set to the LBA-only sentinel."""
    e = bytearray(16)
    e[0] = 0x80 if bootable else 0x00
    e[1], e[2], e[3] = lba_to_chs(start_lba)
    e[4] = part_type & 0xFF
    end = start_lba + sectors - 1
    e[5], e[6], e[7] = lba_to_chs(end)
    struct.pack_into("<I", e, 8, start_lba & 0xFFFFFFFF)
    struct.pack_into("<I", e, 12, min(sectors, 0xFFFFFFFF))
    return bytes(e)


def lba_to_chs(lba, heads=255, spt=63):
    """Return the three on-disk CHS bytes: (head, sector|cyl_hi, cyl_lo).

    Beyond the 1024-cylinder limit the standard LBA sentinel FE FF FF is used;
    modern Windows ignores CHS entirely and reads only the LBA fields.
    """
    cyl = lba // (heads * spt)
    head = (lba // spt) % heads
    sect = (lba % spt) + 1
    if cyl > 1023:
        return 0xFE, 0xFF, 0xFF
    return head & 0xFF, ((sect & 0x3F) | ((cyl >> 2) & 0xC0)), (cyl & 0xFF)


def parse_mbr(disk):
    """Read and interpret sector 0. Returns dict (never raises)."""
    sec0 = disk.read_lba(0, 1)
    res = {"present": False, "signature_ok": False, "protective": False,
           "entries": [], "disk_sig": None, "raw": sec0,
           "bootcode_nonzero": False, "extended_chain": []}
    if len(sec0) < 512:
        return res
    res["signature_ok"] = (sec0[510:512] == b"\x55\xAA")
    res["disk_sig"] = "%08X" % u32(sec0, 0x1B8)
    res["bootcode_nonzero"] = any(sec0[0:0x1B8])
    ents = []
    for i in range(4):
        raw = sec0[0x1BE + i * 16:0x1BE + (i + 1) * 16]
        if len(raw) < 16:
            break
        e = MbrEntry(raw, slot=i)
        ents.append(e)
    res["entries"] = ents
    res["present"] = res["signature_ok"] and any(not e.empty for e in ents)
    res["protective"] = any(e.type == 0xEE for e in ents)
    # sanity: entries pointing outside the disk mean a bogus/overwritten table
    # A 0xEE protective entry legitimately carries the saturated value
    # 0xFFFFFFFF when the disk does not fit in a 32-bit sector count, so it is
    # never a range error. Counting it as one used to raise a false disk-level
    # blocker on every large GPT disk.
    bad = 0
    for e in ents:
        if e.empty or e.type == 0xEE:
            continue
        if e.start >= disk.sectors or e.start + e.sectors > disk.sectors + 1:
            bad += 1
    res["out_of_range"] = bad
    res["protective_ok"] = None
    for e in ents:
        if e.type == 0xEE:
            expect = min(disk.sectors - 1, 0xFFFFFFFF)
            res["protective_ok"] = (e.start == 1 and
                                    e.sectors in (expect, 0xFFFFFFFF))
            break
    if res["present"] and not res["protective"]:
        res["extended_chain"] = walk_extended(disk, ents)
    return res


def walk_extended(disk, entries, max_links=128):
    """Follow the EBR chain of an extended partition."""
    found = []
    ext = None
    for e in entries:
        if e.type in MBR_EXTENDED and not e.empty:
            ext = e
            break
    if ext is None:
        return found
    base = ext.start
    cur = ext.start
    seen = set()
    for _ in range(max_links):
        if cur in seen or cur >= disk.sectors:
            break
        seen.add(cur)
        sec = disk.read_lba(cur, 1)
        if len(sec) < 512 or sec[510:512] != b"\x55\xAA":
            break
        e0 = MbrEntry(sec[0x1BE:0x1CE], slot=0, base=cur, src="EBR@%d" % cur)
        e1 = MbrEntry(sec[0x1CE:0x1DE], slot=1, base=base, src="EBR@%d" % cur)
        if not e0.empty:
            found.append(e0)
        if e1.empty or e1.type not in MBR_EXTENDED:
            break
        cur = e1.start
    return found


def build_protective_mbr(disk_sectors, keep_bootcode=b""):
    """Standard protective MBR for a GPT disk."""
    sec = bytearray(512)
    if keep_bootcode and len(keep_bootcode) >= 0x1B8:
        sec[0:0x1B8] = keep_bootcode[0:0x1B8]
    n = min(disk_sectors - 1, 0xFFFFFFFF)
    sec[0x1BE:0x1CE] = build_mbr_entry(0xEE, 1, n)
    sec[510:512] = b"\x55\xAA"
    return bytes(sec)


# =============================================================================
# SECTION 7 — GPT parser/builder
# =============================================================================

class GptEntry(object):
    __slots__ = ("index", "type_guid", "part_guid", "first", "last",
                 "attrs", "name", "raw")

    def __init__(self, raw, index):
        self.raw = raw
        self.index = index
        self.type_guid = guid_to_str(raw[0:16])
        self.part_guid = guid_to_str(raw[16:32])
        self.first = u64(raw, 32)
        self.last = u64(raw, 40)
        self.attrs = u64(raw, 48)
        try:
            self.name = raw[56:128].decode("utf-16-le").split("\x00")[0]
        except Exception:
            self.name = ""

    @property
    def used(self):
        return self.raw[0:16] != ZERO_GUID and self.last >= self.first > 0

    @property
    def sectors(self):
        return self.last - self.first + 1

    def type_name(self):
        return GPT_TYPES.get(self.type_guid, self.type_guid)


def parse_gpt_header(buf):
    """Parse a 512+ byte buffer containing a GPT header. Returns dict or None."""
    if len(buf) < 92 or buf[0:8] != GPT_SIG:
        return None
    h = {
        "revision": "%d.%d" % (u16(buf, 10), u16(buf, 8)),
        "header_size": u32(buf, 12),
        "header_crc": u32(buf, 16),
        "current_lba": u64(buf, 24),
        "backup_lba": u64(buf, 32),
        "first_usable": u64(buf, 40),
        "last_usable": u64(buf, 48),
        "disk_guid": guid_to_str(buf[56:72]),
        "entry_lba": u64(buf, 72),
        "entry_count": u32(buf, 80),
        "entry_size": u32(buf, 84),
        "entry_crc": u32(buf, 88),
        "raw": bytes(buf[:max(92, min(u32(buf, 12), len(buf)))]),
    }
    hs = h["header_size"]
    if not (92 <= hs <= len(buf)):
        h["header_crc_ok"] = False
        return h
    tmp = bytearray(buf[:hs])
    struct.pack_into("<I", tmp, 16, 0)
    h["header_crc_ok"] = (crc32(bytes(tmp)) == h["header_crc"])
    return h


def read_gpt(disk, which="primary"):
    """Read primary or backup GPT. Returns dict with header/entries/validity."""
    res = {"which": which, "present": False, "header": None, "entries": [],
           "header_crc_ok": False, "entries_crc_ok": False, "valid": False,
           "errors": [], "header_lba": None, "entry_lba": None}
    total = disk.sectors
    hdr_lba = 1 if which == "primary" else total - 1
    if hdr_lba < 0 or hdr_lba >= total:
        res["errors"].append("header LBA out of range")
        return res
    res["header_lba"] = hdr_lba
    buf = disk.read_lba(hdr_lba, 1)
    h = parse_gpt_header(buf)
    if not h:
        res["errors"].append("no EFI PART signature at LBA %d" % hdr_lba)
        return res
    res["present"] = True
    res["header"] = h
    res["header_sector"] = bytes(buf)      # kept verbatim for byte-for-byte work
    res["header_crc_ok"] = h.get("header_crc_ok", False)
    if not res["header_crc_ok"]:
        res["errors"].append("header CRC32 mismatch")
    esz = h["entry_size"] or GPT_ENTRY_SIZE
    ecnt = h["entry_count"] or GPT_ENTRY_COUNT
    if not (128 <= esz <= 4096) or not (1 <= ecnt <= 4096):
        res["errors"].append("insane entry geometry (%d x %d)" % (ecnt, esz))
        return res
    elba = h["entry_lba"]
    res["entry_lba"] = elba
    nbytes = esz * ecnt
    ebuf = disk.read_at(elba * disk.sector, nbytes)
    if len(ebuf) < nbytes:
        res["errors"].append("entry array truncated")
        ebuf = ebuf + bytes(nbytes - len(ebuf))
    res["entries_crc_ok"] = (crc32(ebuf) == h["entry_crc"])
    if not res["entries_crc_ok"]:
        res["errors"].append("entry array CRC32 mismatch")
    ents = []
    for i in range(ecnt):
        raw = ebuf[i * esz:(i + 1) * esz]
        if len(raw) < 128:
            break
        e = GptEntry(raw[:128], i)
        if e.used:
            ents.append(e)
    res["entries"] = ents
    res["entry_bytes"] = ebuf
    res["valid"] = res["header_crc_ok"] and res["entries_crc_ok"]
    # geometry sanity against the real disk size
    # In the PRIMARY header AlternateLBA points at the last sector of the disk.
    # In the BACKUP header it points back at LBA 1. Applying the primary rule to
    # both sides produced a false "mismatch" on every healthy disk.
    if which == "primary":
        exp_my, exp_alt = 1, total - 1
    else:
        exp_my, exp_alt = total - 1, 1
    mism = []
    if h["current_lba"] != exp_my:
        mism.append("MyLBA=%d, expected %d" % (h["current_lba"], exp_my))
    if h["backup_lba"] != exp_alt:
        mism.append("AlternateLBA=%d, expected %d" % (h["backup_lba"], exp_alt))
    res["geometry_mismatch"] = bool(mism)
    for m in mism:
        res["errors"].append(m)
    return res


def build_gpt(disk_sectors, sector_size, partitions, disk_guid=None,
              entry_count=GPT_ENTRY_COUNT, keep_guids=None):
    """Create primary+backup GPT structures.

    partitions: list of dicts {first, last, type_guid, name, part_guid, attrs}
    Returns dict with byte blobs and their LBA placement.
    """
    esz = GPT_ENTRY_SIZE
    entries_sectors = (entry_count * esz + sector_size - 1) // sector_size
    first_usable = 2 + entries_sectors
    last_usable = disk_sectors - 1 - entries_sectors - 1
    if last_usable <= first_usable:
        raise DiskError("disk too small for GPT")

    arr = bytearray(entry_count * esz)
    for i, p in enumerate(partitions):
        if i >= entry_count:
            break
        off = i * esz
        arr[off:off + 16] = str_to_guid(p.get("type_guid") or GUID_MSDATA)
        pg = p.get("part_guid")
        arr[off + 16:off + 32] = str_to_guid(pg) if pg else new_guid()
        struct.pack_into("<Q", arr, off + 32, int(p["first"]))
        struct.pack_into("<Q", arr, off + 40, int(p["last"]))
        struct.pack_into("<Q", arr, off + 48, int(p.get("attrs") or 0))
        nm = (p.get("name") or "")[:36]
        arr[off + 56:off + 56 + len(nm.encode("utf-16-le"))] = nm.encode("utf-16-le")
    arr = bytes(arr)
    ecrc = crc32(arr)
    dg = str_to_guid(disk_guid) if disk_guid else new_guid()

    def mk_header(cur_lba, bak_lba, ent_lba):
        h = bytearray(sector_size)
        h[0:8] = GPT_SIG
        struct.pack_into("<I", h, 8, 0x00010000)
        struct.pack_into("<I", h, 12, GPT_HEADER_SIZE)
        struct.pack_into("<I", h, 16, 0)
        struct.pack_into("<I", h, 20, 0)
        struct.pack_into("<Q", h, 24, cur_lba)
        struct.pack_into("<Q", h, 32, bak_lba)
        struct.pack_into("<Q", h, 40, first_usable)
        struct.pack_into("<Q", h, 48, last_usable)
        h[56:72] = dg
        struct.pack_into("<Q", h, 72, ent_lba)
        struct.pack_into("<I", h, 80, entry_count)
        struct.pack_into("<I", h, 84, esz)
        struct.pack_into("<I", h, 88, ecrc)
        struct.pack_into("<I", h, 16, crc32(bytes(h[:GPT_HEADER_SIZE])))
        return bytes(h)

    bak_entries_lba = disk_sectors - 1 - entries_sectors
    return {
        "primary_header": mk_header(1, disk_sectors - 1, 2),
        "primary_header_lba": 1,
        "primary_entries": arr,
        "primary_entries_lba": 2,
        "backup_header": mk_header(disk_sectors - 1, 1, bak_entries_lba),
        "backup_header_lba": disk_sectors - 1,
        "backup_entries": arr,
        "backup_entries_lba": bak_entries_lba,
        "first_usable": first_usable,
        "last_usable": last_usable,
        "disk_guid": guid_to_str(dg),
    }


# =============================================================================

# --- byte-for-byte GPT surgery ------------------------------------------------
# Recovery rule: never regenerate a structure that already exists on the disk.
# Copy it verbatim and change only the fields that MUST change (the location
# fields), then recompute the header CRC. entry_size, revision, header_size,
# reserved bytes, disk GUID and the entry array itself stay untouched.

def gpt_entries_sectors(header, sector_size):
    esz = header.get("entry_size") or GPT_ENTRY_SIZE
    ecnt = header.get("entry_count") or GPT_ENTRY_COUNT
    return (esz * ecnt + sector_size - 1) // sector_size


def gpt_transplant_header(src_sector, sector_size, my_lba, alt_lba, entry_lba,
                          last_usable=None):
    """Copy a GPT header sector verbatim, changing only location fields."""
    if len(src_sector) < 92:
        raise DiskError("source GPT header too short")
    h = bytearray(src_sector[:sector_size].ljust(sector_size, b"\x00"))
    hs = u32(h, 12)
    if not (92 <= hs <= sector_size):
        raise DiskError("source GPT header has an insane HeaderSize (%d)" % hs)
    struct.pack_into("<Q", h, 24, my_lba)
    struct.pack_into("<Q", h, 32, alt_lba)
    struct.pack_into("<Q", h, 72, entry_lba)
    if last_usable is not None:
        struct.pack_into("<Q", h, 48, last_usable)
    struct.pack_into("<I", h, 16, 0)
    struct.pack_into("<I", h, 16, crc32(bytes(h[:hs])))
    return bytes(h)


def gpt_recrc_header(src_sector, sector_size, entry_bytes):
    """Return the same header sector with only its two CRC fields corrected."""
    h = bytearray(src_sector[:sector_size].ljust(sector_size, b"\x00"))
    hs = u32(h, 12)
    if not (92 <= hs <= sector_size):
        raise DiskError("insane HeaderSize (%d)" % hs)
    struct.pack_into("<I", h, 88, crc32(entry_bytes))
    struct.pack_into("<I", h, 16, 0)
    struct.pack_into("<I", h, 16, crc32(bytes(h[:hs])))
    return bytes(h)


def gpt_entries_plausible(g, disk_sectors):
    """Sanity of an on-disk entry array, so 'fix CRC' cannot bless garbage."""
    reasons = []
    ents = g.get("entries") or []
    if not ents:
        reasons.append("no used partition entries")
    h = g.get("header") or {}
    fu = h.get("first_usable", 0)
    lu = h.get("last_usable", 0)
    spans = []
    for e in ents:
        if e.first < 1 or e.last < e.first:
            reasons.append("entry %d has an inverted or zero range" % e.index)
        if e.last >= disk_sectors:
            reasons.append("entry %d ends past the end of the disk" % e.index)
        if fu and lu and (e.first < fu or e.last > lu):
            reasons.append("entry %d falls outside the usable LBA range" % e.index)
        spans.append((e.first, e.last, e.index))
    spans.sort()
    for i in range(1, len(spans)):
        if spans[i][0] <= spans[i - 1][1]:
            reasons.append("entries %d and %d overlap" % (spans[i - 1][2], spans[i][2]))
    return (not reasons), reasons


# =============================================================================
# SECTION 8 — Evidence engine
# =============================================================================
# A candidate partition is described by independent signals. Nothing here
# decides anything; it only records what was observed and why. The Repair
# Planner and the Write Gate consume this and never re-derive it.
# =============================================================================

# Offsets partitions realistically start on. Used both by the fast sweep and
# by the alignment signal.
COMMON_STARTS = [2048, 63, 34, 40, 1, 8, 16, 32, 64, 128, 256, 1024, 4096,
                 8192, 2056, 6144, 264192, 206848, 1026048]

SIGNAL_WEIGHTS = {
    "partition_table": 25,
    "vbr_signature": 20,
    "bpb_consistency": 15,
    "mirror_signature": 12,
    "mirror_bpb_match": 20,
    "mirror_position": 25,
    "exfat_checksum": 20,
    "partition_offset": 10,
    "hidden_sectors": 10,
    "refs_superblock": 15,
    "extent_agreement": 15,
    "alignment": 5,
    "bounds": 5,
}

STRONG_CONFIDENCE = 0.75
MEDIUM_CONFIDENCE = 0.50


class Evidence(object):
    """Signals, score and blockers for one candidate partition."""

    def __init__(self, fs_name):
        self.fs = fs_name or "-"
        self.signals = {}          # name -> {"value": True/False/None, "why": str}
        self.blockers = []         # [(key, why)]
        self.extent_source = None  # what proved the volume length, if anything

    # -- recording ---------------------------------------------------------
    def set(self, name, value, why=""):
        self.signals[name] = {"value": None if value is None else bool(value), "why": why}

    def na(self, name, why=""):
        """Signal does not apply to this filesystem; excluded from scoring."""
        self.signals[name] = {"value": None, "why": why}

    def block(self, key, why):
        if key not in [k for k, _ in self.blockers]:
            self.blockers.append((key, why))

    # -- scoring -----------------------------------------------------------
    @property
    def applicable(self):
        return [k for k, v in self.signals.items() if v["value"] is not None]

    @property
    def score(self):
        return sum(SIGNAL_WEIGHTS.get(k, 0) for k in self.applicable
                   if self.signals[k]["value"])

    @property
    def max_score(self):
        return sum(SIGNAL_WEIGHTS.get(k, 0) for k in self.applicable) or 1

    @property
    def confidence(self):
        return float(self.score) / float(self.max_score)

    @property
    def extent_verified(self):
        return self.extent_source is not None

    @property
    def level(self):
        if self.blockers:
            return "blocked"
        if self.confidence >= STRONG_CONFIDENCE and self.extent_verified:
            return "strong"
        if self.confidence >= MEDIUM_CONFIDENCE:
            return "medium"
        return "weak"

    def passed(self):
        return [k for k in self.applicable if self.signals[k]["value"]]

    def failed(self):
        return [k for k in self.applicable if not self.signals[k]["value"]]

    def to_dict(self):
        return {
            "fs": self.fs,
            "score": self.score, "max_score": self.max_score,
            "confidence": round(self.confidence, 3),
            "level": self.level,
            "extent_verified": self.extent_verified,
            "extent_source": self.extent_source,
            "signals": {k: dict(v, state="UNKNOWN" if v["value"] is None else
                                  ("VERIFIED" if v["value"] else "REJECTED"))
                        for k, v in self.signals.items()},
            "blockers": [{"key": k, "why": w} for k, w in self.blockers],
        }


def build_evidence(disk, p):
    """Collect every independent signal we can for one candidate partition."""
    fs = p.fs
    name = fs["fs"] if fs else None
    ev = Evidence(name)
    total = disk.sectors

    # ---- bounds / alignment ----------------------------------------------
    in_bounds = (0 <= p.start < total) and (p.sectors > 0) and (p.end < total)
    ev.set("bounds", in_bounds,
           "LBA %d..%d vs disk last LBA %d" % (p.start, p.end, total - 1))
    if not in_bounds:
        ev.block("out_of_bounds", "کاندید از محدوده دیسک بیرون می‌زند "
                                  "(%d..%d، آخرین LBA دیسک %d)" % (p.start, p.end, total - 1))
    mib = MIB // disk.sector
    aligned = (p.start % mib == 0) or (p.start in COMMON_STARTS)
    ev.set("alignment", aligned, "start LBA %d" % p.start)

    # ---- came from a partition table? -------------------------------------
    from_table = p.source in ("MBR", "GPT", "GPT-BACKUP") or p.source.startswith("EBR")
    ev.set("partition_table", from_table, "source=%s" % p.source)

    if not fs and type_expects_no_fs(p):
        ev.set("vbr_signature", True,
               "partition type %s is defined to carry no filesystem"
               % (p.type_name or p.type_id))
        ev.set("bpb_consistency", True, "not applicable to this partition type")
        for k in ("mirror_signature", "mirror_bpb_match", "mirror_position",
                  "exfat_checksum", "partition_offset", "hidden_sectors",
                  "refs_superblock", "extent_agreement"):
            ev.na(k, "reserved partition type")
        ev.extent_source = "partition table entry (reserved type)"
        return ev

    if not fs:
        ev.set("vbr_signature", False, "no filesystem signature at the start LBA")
        ev.set("bpb_consistency", False, "no BPB to check")
        for k in ("mirror_signature", "mirror_bpb_match", "mirror_position",
                  "exfat_checksum", "partition_offset", "hidden_sectors",
                  "refs_superblock", "extent_agreement"):
            ev.na(k, "no filesystem detected")
        if from_table:
            ev.extent_source = "partition table entry"
        else:
            ev.block("extent_unverified", "نه فایل‌سیستمی شناسایی شد نه ورودی جدولی هست")
        return ev

    ev.set("vbr_signature", fs["conf"] >= 0.9,
           "%s signature, detector confidence %.2f" % (name, fs["conf"]))
    f = fs.get("fields") or {}

    if name == "NTFS":
        sane = ntfs_fields_sane(f)
        ev.set("bpb_consistency", sane, _ntfs_why(f))
        _ntfs_mirror_evidence(disk, p, f, ev)
        ev.na("exfat_checksum", "not exFAT")
        ev.na("partition_offset", "not exFAT")
        ev.set("hidden_sectors", f.get("hidden_sectors") == p.start,
               "BPB_HiddSec=%d vs start LBA %d" % (f.get("hidden_sectors", -1), p.start))
        ev.na("refs_superblock", "not ReFS")
    elif name == "exFAT":
        sane = (f.get("bps") in (512, 1024, 2048, 4096)
                and 0 < f.get("volume_length", 0) < (1 << 48)
                and f.get("cluster_count", 0) > 0)
        ev.set("bpb_consistency", sane,
               "bps=%s volume_length=%s clusters=%s" %
               (f.get("bps"), f.get("volume_length"), f.get("cluster_count")))
        cs_ok, cs_why = exfat_checksum_ok(disk, p.start, f.get("bps") or disk.sector)
        ev.set("exfat_checksum", cs_ok, cs_why)
        ev.set("partition_offset", f.get("partition_offset") == p.start,
               "PartitionOffset=%d vs start LBA %d" %
               (f.get("partition_offset", -1), p.start))
        _exfat_mirror_evidence(disk, p, f, ev)
        ev.na("hidden_sectors", "exFAT uses PartitionOffset instead")
        ev.na("refs_superblock", "not ReFS")
        if cs_ok and f.get("partition_offset") == p.start and sane:
            ev.extent_source = "exFAT VBR checksum + PartitionOffset"
    elif name in FAT_FS:
        sane = fat_fields_sane(f)
        geom_ok = _fat_geometry_ok(f)
        ev.set("bpb_consistency", sane and geom_ok, _fat_why(f, geom_ok))
        ev.set("hidden_sectors", f.get("hidden_sectors") == p.start,
               "BPB_HiddSec=%d vs start LBA %d" % (f.get("hidden_sectors", -1), p.start))
        ev.na("exfat_checksum", "not exFAT")
        ev.na("partition_offset", "not exFAT")
        ev.na("refs_superblock", "not ReFS")
        if name == "FAT32":
            _fat32_mirror_evidence(disk, p, f, ev, geom_ok and sane)
        else:
            for k in ("mirror_signature", "mirror_bpb_match", "mirror_position"):
                ev.na(k, "FAT12/16 has no backup boot sector")
    elif name == "ReFS":
        sane = (f.get("bps") in (512, 1024, 2048, 4096)
                and 0 < f.get("total_sectors", 0) < (1 << 48))
        ev.set("bpb_consistency", sane,
               "bps=%s total_sectors=%s version=%s" %
               (f.get("bps"), f.get("total_sectors"), f.get("version")))
        # v1.1 declared "ReFS has no VBR mirror" as a hard rule. Real disks show
        # a copy of the volume header in the last sector of the volume, so the
        # rule was wrong. It is now a checked signal like any other, and when it
        # validates it proves the volume length.
        cp = find_refs_header_copy(disk, p.start, f.get("total_sectors") or 0)
        ev.set("mirror_signature", bool(cp),
               ("ReFS volume header copy at LBA %d" % cp["lba"]) if cp
               else "no ReFS volume header copy at the end of the declared volume")
        if cp:
            same = (cp["header"]["num_sectors"] == f.get("total_sectors")
                    and cp["header"]["bytes_per_sector"] == f.get("bps"))
            ev.set("mirror_bpb_match", same,
                   "copy declares %d sectors / %d bps"
                   % (cp["header"]["num_sectors"], cp["header"]["bytes_per_sector"]))
            ev.set("mirror_position", same,
                   "copy sits at start+NumberOfSectors-1, which proves the length"
                   if same else "copy disagrees with the primary header")
            if same:
                ev.extent_source = "ReFS volume header copy at the end of the volume"
        else:
            ev.na("mirror_bpb_match", "no header copy found")
            ev.set("mirror_position", False, "no header copy at the expected LBA")
        ev.na("exfat_checksum", "not exFAT")
        ev.na("partition_offset", "not exFAT")
        ev.na("hidden_sectors", "ReFS has no BPB_HiddSec")
        found, why = refs_superblock_evidence(disk, p, f)
        ev.set("refs_superblock", found, why)
    elif name == "BitLocker":
        ev.set("bpb_consistency", True, "FVE header present")
        for k in ("mirror_signature", "mirror_bpb_match", "mirror_position",
                  "exfat_checksum", "partition_offset", "hidden_sectors",
                  "refs_superblock"):
            ev.na(k, "encrypted volume")
        ev.block("encrypted", "ولوم BitLocker است؛ بدون کلید بازیابی هیچ ترمیم "
                              "ساختاری داده را قابل خواندن نمی‌کند")
    else:
        ev.set("bpb_consistency", fs["conf"] >= 0.9, "detector-level sanity only")
        for k in ("mirror_signature", "mirror_bpb_match", "mirror_position",
                  "exfat_checksum", "partition_offset", "hidden_sectors",
                  "refs_superblock"):
            ev.na(k, "no mirror model for %s" % name)

    # ---- does the filesystem agree with the table about the size? ---------
    declared = fs.get("sectors") or 0
    if from_table and declared:
        # NTFS and FAT fill their partition exactly. ReFS and the Linux
        # filesystems do not have to, so "shorter than the partition" is normal
        # for them and must not be scored as a failure.
        if name in ("NTFS", "FAT32", "FAT16", "FAT12", "exFAT"):
            agree = abs(declared - p.sectors) <= 1
            why = ("filesystem says %d sectors, table entry says %d"
                   % (declared, p.sectors))
        else:
            agree = declared <= p.sectors
            why = ("filesystem occupies %d of the partition's %d sectors "
                   "(%s unused, normal for %s)"
                   % (declared, p.sectors,
                      human((p.sectors - declared) * disk.sector), name))
        ev.set("extent_agreement", agree, why)
        if declared > p.sectors:
            ev.block("extent_conflict",
                     "فایل‌سیستم %d سکتور ادعا می‌کند ولی ورودی جدول %d سکتور است — "
                     "فایل‌سیستم از پارتیشن بزرگ‌تر است" % (declared, p.sectors))
    else:
        ev.na("extent_agreement", "only one source of length is available")

    # ---- extent proof -----------------------------------------------------
    if ev.extent_source is None and from_table and in_bounds:
        ev.extent_source = "partition table entry"
    if ev.extent_source is None:
        ev.block("extent_unverified",
                 "طول ولوم از هیچ منبع معتبری اثبات نشد (نه آینه در فاصله مورد "
                 "انتظار، نه ورودی جدول) — start معلوم است ولی end حدس است")
    return ev


def _ntfs_why(f):
    return ("bps=%s spc=%s total=%s mft=%s mftmirr=%s reserved=%s sig=%s" %
            (f.get("bps"), f.get("spc"), f.get("total_sectors"), f.get("mft_lcn"),
             f.get("mftmirr_lcn"), f.get("reserved"), f.get("boot_sig")))


def _fat_why(f, geom_ok):
    return ("bps=%s spc=%s fats=%s reserved=%s total=%s geometry=%s" %
            (f.get("bps"), f.get("spc"), f.get("num_fats"), f.get("reserved"),
             f.get("total_sectors"), "ok" if geom_ok else "inconsistent"))


def _fat_geometry_ok(f):
    """reserved + FATs + root dir must fit inside the declared volume."""
    try:
        fatsz = f.get("fat_size32") or f.get("fat_size16") or 0
        root = ((f.get("root_entries", 0) * 32) + f["bps"] - 1) // f["bps"]
        meta = f["reserved"] + f["num_fats"] * fatsz + root
        return 0 < meta < f["total_sectors"]
    except Exception:
        return False


def _ntfs_mirror_evidence(disk, p, f, ev):
    """NTFS keeps a copy of its boot sector in the last sector of the volume.

    Because the mirror sits at exactly TotalSectors sectors from the start,
    finding a matching copy there is what proves the volume length. This is the
    only NTFS length proof this tool accepts.
    """
    t = f.get("total_sectors") or 0
    exp = p.start + t
    if t <= 0 or exp >= disk.sectors:
        ev.set("mirror_signature", False, "expected mirror LBA %d is outside the disk" % exp)
        ev.na("mirror_bpb_match", "no mirror to compare")
        ev.set("mirror_position", False, "unusable expected position")
        return
    sec = disk.read_at(exp * disk.sector, disk.sector)
    got = sec[3:11] == b"NTFS    "
    ev.set("mirror_signature", got, "NTFS mirror at LBA %d: %s" % (exp, "found" if got else "absent"))
    if not got:
        ev.na("mirror_bpb_match", "no mirror found")
        ev.set("mirror_position", False, "no mirror at the expected LBA %d" % exp)
        _detect_mirror_copy(disk, p, f, ev)
        return
    mf = ntfs_fields(sec)
    match, diffs = bpb_match("NTFS", f, mf)
    ev.set("mirror_bpb_match", match,
           "all key BPB fields identical" if match else "; ".join(diffs[:4]))
    table_ok = True
    why = "mirror sits exactly TotalSectors (%d) from the start" % t
    if p.source in ("MBR", "GPT", "GPT-BACKUP") or p.source.startswith("EBR"):
        table_ok = (exp == p.end)
        if not table_ok:
            why = ("mirror at LBA %d but the table says the partition ends at %d"
                   % (exp, p.end))
    ev.set("mirror_position", bool(match and table_ok), why)
    if match and table_ok:
        ev.extent_source = "NTFS backup boot sector at start+TotalSectors"
    _detect_mirror_copy(disk, p, f, ev)


def _fat32_mirror_evidence(disk, p, f, ev, base_sane):
    bk = f.get("bk_boot_sec") or 0
    if not (0 < bk < 64):
        ev.set("mirror_signature", False, "BPB_BkBootSec=%d is not usable" % bk)
        ev.na("mirror_bpb_match", "no mirror")
        ev.set("mirror_position", False, "no backup boot sector declared")
        return
    exp = p.start + bk
    sec = disk.read_at(exp * disk.sector, disk.sector)
    got = (sec[0x52:0x5A] == b"FAT32   ") or _looks_like_fat32(sec)
    ev.set("mirror_signature", got,
           "FAT32 backup boot sector at LBA %d (BPB_BkBootSec=%d): %s"
           % (exp, bk, "found" if got else "absent"))
    if not got:
        ev.na("mirror_bpb_match", "no mirror found")
        ev.set("mirror_position", False, "nothing at the declared backup sector")
        _detect_mirror_copy(disk, p, f, ev)
        return
    mf = fat_fields(sec, 32)
    match, diffs = bpb_match("FAT32", f, mf)
    ev.set("mirror_bpb_match", match,
           "backup BPB identical to primary" if match else "; ".join(diffs[:4]))
    ev.set("mirror_position", bool(match),
           "two independent copies of TotalSectors agree" if match
           else "backup exists but disagrees")
    if match and base_sane:
        ev.extent_source = "FAT32 backup boot sector agreeing on TotalSectors"
    _detect_mirror_copy(disk, p, f, ev)


def _exfat_mirror_evidence(disk, p, f, ev):
    exp = p.start + 12
    sec = disk.read_at(exp * disk.sector, disk.sector)
    got = sec[3:11] == b"EXFAT   "
    ev.set("mirror_signature", got,
           "exFAT VBR mirror at LBA %d: %s" % (exp, "found" if got else "absent"))
    if not got:
        ev.na("mirror_bpb_match", "no mirror found")
        ev.set("mirror_position", False, "no mirror at start+12")
        _detect_mirror_copy(disk, p, f, ev)
        return
    mf = exfat_fields(sec)
    match, diffs = bpb_match("exFAT", f, mf)
    ev.set("mirror_bpb_match", match,
           "mirror VBR identical" if match else "; ".join(diffs[:4]))
    ev.set("mirror_position", True, "mirror present at the fixed offset 12")
    _detect_mirror_copy(disk, p, f, ev)


def _detect_mirror_copy(disk, p, f, ev):
    """Is this candidate itself a backup copy rather than a volume start?

    A lone mirror found by signature carving looks exactly like a volume start
    and would produce a ghost partition offset by the volume length. Check the
    position where the real start would have to be.
    """
    name = ev.fs
    if name == "NTFS":
        back = f.get("total_sectors") or 0
    elif name == "FAT32":
        back = f.get("bk_boot_sec") or 0
    elif name == "exFAT":
        back = 12
    else:
        return
    if back <= 0 or p.start - back < 0:
        return
    origin = p.start - back

    # Path 1 — the VBR names its own volume start. If this copy sits exactly
    # `back` sectors after the LBA it claims to start at, it IS the mirror.
    # This works even when the primary VBR has been destroyed, which is exactly
    # the case that would otherwise produce a ghost partition.
    declared_start = (f.get("partition_offset") if name == "exFAT"
                      else f.get("hidden_sectors"))
    if declared_start and declared_start != p.start and \
            p.start - declared_start == back:
        ev.block("is_mirror_copy",
                 "این بوت‌سکتور اعلام می‌کند ولومش از LBA %d شروع می‌شود و خودش "
                 "دقیقاً %d سکتور بعدتر است — یعنی نسخه آینه است، نه شروع ولوم"
                 % (declared_start, back))
        return

    # Path 2 — the primary is still readable and identical.
    sec = disk.read_at(origin * disk.sector, disk.sector)
    magic = {"NTFS": b"NTFS    ", "FAT32": None, "exFAT": b"EXFAT   "}.get(name)
    if name == "FAT32":
        hit = (sec[0x52:0x5A] == b"FAT32   ")
        of = fat_fields(sec, 32) if hit else None
    else:
        hit = (sec[3:11] == magic)
        of = (ntfs_fields(sec) if name == "NTFS" else exfat_fields(sec)) if hit else None
    if not hit:
        return
    match, _ = bpb_match(name, f, of)
    if match:
        ev.block("is_mirror_copy",
                 "این کاندید خودش نسخه آینه ولومی است که در LBA %d شروع می‌شود؛ "
                 "شروع ولوم نیست" % origin)
        ev.signals.setdefault("mirror_signature", {})
        ev.set("mirror_signature", True, "matched the primary VBR at LBA %d" % origin)


def refs_superblock_evidence(disk, p, f, window=8 * MIB):
    """Look for ReFS's duplicated superblock structures near the volume end.

    Used only as corroboration of the declared extent. This tool never writes
    any ReFS structure.
    """
    t = f.get("total_sectors") or 0
    if t <= 0:
        return False, "ReFS declares no usable volume length"
    end = p.start + t
    if end > disk.sectors:
        return False, "declared ReFS length runs past the end of the disk"
    span = min(window, t * disk.sector)
    off = (end * disk.sector) - span
    if off < 0:
        return False, "volume too small to search"
    buf = disk.read_at(off, span)
    hits = []
    for sig in (REFS_SUPERBLOCK_SIG, REFS_CHECKPOINT_SIG):
        i = buf.find(sig)
        while i >= 0 and len(hits) < 4:
            hits.append((sig.decode(), (off + i) // disk.sector))
            i = buf.find(sig, i + 1)
    if hits:
        return True, "ReFS structures near the volume end: " + ", ".join(
            "%s@LBA%d" % h for h in hits[:3])
    return False, "no ReFS superblock/checkpoint structure found in the last %s" % human(span)


def mark_overlaps(parts):
    """Set the overlap blocker on any pair of candidates that intersect."""
    ordered = sorted([p for p in parts if p.ev and not p.ev.blockers],
                     key=lambda x: x.start)
    for i in range(1, len(ordered)):
        a, b = ordered[i - 1], ordered[i]
        if b.start <= a.end:
            a.ev.block("overlap", "با کاندید #%d همپوشانی دارد (%d..%d و %d..%d)"
                       % (b.num, a.start, a.end, b.start, b.end))
            b.ev.block("overlap", "با کاندید #%d همپوشانی دارد (%d..%d و %d..%d)"
                       % (a.num, b.start, b.end, a.start, a.end))


# =============================================================================
# SECTION 9 — Scanner
# =============================================================================

PROBE_BYTES = 1 * MIB + 8 * KIB
QUICK_PROBE_BYTES = 68 * KIB


class Part(object):
    """Unified candidate record. `ev` is filled by the Evidence Builder."""
    _n = 0

    def __init__(self, start, sectors, source, type_id="", type_name="",
                 name="", fs=None, guid="", attrs=0, slot=None):
        Part._n += 1
        self.num = Part._n
        self.start = int(start)
        self.sectors = int(sectors)
        self.source = source
        self.type_id = type_id
        self.type_name = type_name
        self.name = name
        self.fs = fs
        self.guid = guid
        self.attrs = attrs
        self.slot = slot
        self.ev = None

    @property
    def end(self):
        return self.start + self.sectors - 1

    def fs_name(self):
        return self.fs["fs"] if self.fs else "-"

    @property
    def level(self):
        return self.ev.level if self.ev else "?"

    def to_dict(self, sector=512):
        return {
            "num": self.num, "start_lba": self.start, "end_lba": self.end,
            "sectors": self.sectors, "size": self.sectors * sector,
            "size_h": human(self.sectors * sector), "source": self.source,
            "type_id": self.type_id, "type_name": self.type_name,
            "name": self.name, "guid": self.guid,
            "fs": self.fs["fs"] if self.fs else None,
            "fs_detail": (self.fs or {}).get("detail"),
            "fs_fields": (self.fs or {}).get("fields"),
            "evidence": self.ev.to_dict() if self.ev else None,
        }


class ScanResult(object):
    def __init__(self, disk):
        self.disk = disk
        self.run_id = str(uuid.uuid4())
        self.source_fingerprint = None
        self.fingerprint_error = None
        self.transactions = []
        self.scheme = "UNKNOWN"
        self.mbr = None
        self.gpt_p = None
        self.gpt_b = None
        self.parts = []
        self.carved = []
        self.warnings = []
        self.blockers = []      # disk-level, [(key, why)]
        self.superfloppy = None
        self.elapsed = 0.0
        self.deep_done = False
        self.deep_scope = {"state": "UNKNOWN", "reason": "not requested"}
        self.container = None

    def add_warn(self, s):
        if s not in self.warnings:
            self.warnings.append(s)

    def block(self, key, why):
        if key not in [k for k, _ in self.blockers]:
            self.blockers.append((key, why))

    def blocker_keys(self):
        return [k for k, _ in self.blockers]

    @property
    def all_parts(self):
        return self.parts + self.carved

    def to_dict(self):
        d = self.disk
        return {
            "tool": "DiskDoctor", "version": VERSION,
            "generated": core.timestamp(),
            "run_id": self.run_id, "tool_version": VERSION,
            "source_fingerprint": self.source_fingerprint,
            "source_identity_state": "VERIFIED" if self.source_fingerprint else "UNKNOWN",
            "fingerprint_error": self.fingerprint_error,
            "environment": {"python": sys.version, "platform": sys.platform},
            "diagnosis_state": "BLOCKED" if self.blockers else "INFERRED",
            "final_verdict": "DAMAGED_ANALYZED" if self.blockers or self.warnings else "UNKNOWN",
            "rejected_candidates": [p.to_dict(d.sector) for p in self.all_parts if p.level in ("weak", "blocked")],
            "transaction_ids": self.transactions,
            "target": d.path, "size": d.size, "size_h": human(d.size),
            "sector_size": d.sector, "sectors": d.sectors,
            "scheme": self.scheme, "container": self.container,
            "mbr": {
                "signature_ok": self.mbr["signature_ok"],
                "protective": self.mbr["protective"],
                "disk_signature": self.mbr["disk_sig"],
                "bootcode": self.mbr["bootcode_nonzero"],
                "out_of_range": self.mbr.get("out_of_range"),
            } if self.mbr else None,
            "gpt_primary": _gpt_dict(self.gpt_p),
            "gpt_backup": _gpt_dict(self.gpt_b),
            "partitions": [p.to_dict(d.sector) for p in self.parts],
            "carved": [p.to_dict(d.sector) for p in self.carved],
            "warnings": self.warnings,
            "disk_blockers": [{"key": k, "why": w} for k, w in self.blockers],
            "deep_scan": self.deep_done,
            "deep_scope": self.deep_scope,
            "elapsed_sec": round(self.elapsed, 3),
        }


def _gpt_dict(g):
    if not g:
        return None
    h = g.get("header") or {}
    return {
        "present": g["present"], "valid": g["valid"],
        "header_crc_ok": g["header_crc_ok"], "entries_crc_ok": g["entries_crc_ok"],
        "header_lba": g.get("header_lba"), "entry_lba": g.get("entry_lba"),
        "disk_guid": h.get("disk_guid"), "entry_count": h.get("entry_count"),
        "entry_size": h.get("entry_size"), "revision": h.get("revision"),
        "first_usable": h.get("first_usable"), "last_usable": h.get("last_usable"),
        "backup_lba": h.get("backup_lba"),
        "geometry_mismatch": g.get("geometry_mismatch"),
        "errors": g.get("errors", []),
        "partition_count": len(g.get("entries", [])),
    }


def detect_container(disk):
    head = disk.read_at(0, 4096)
    if not head:
        return None
    if head[0:4] == b"KDMV":
        return ("VMDK sparse (monolithicSparse/streamOptimized)",
                "این فایل یک VMDK فشرده/اسپارس است، نه دیسک خام. اول به flat "
                "تبدیل یا در ویندوز Attach کن.")
    if b"# Disk DescriptorFile" in head[:2048]:
        return ("VMDK descriptor (text)",
                "این فقط فایل توصیف‌گر VMDK است. فایل -flat.vmdk یا دیسک Attach "
                "شده را هدف بگیر.")
    if head[0:8] == b"conectix":
        return ("VHD footer at start", "هدف را دیسک Attach شده بگذار.")
    if head[0:8] == b"vhdxfile":
        return ("VHDX", "این VHDX است، نه دیسک خام. اول Mount/Attach کن.")
    if head[0:3] == b"QFI":
        return ("QCOW2", "این QCOW2 است. اول convert یا nbd mount کن.")
    return None


def scan(disk, deep=False, deep_step=MIB, deep_limit=0, time_budget=0,
         ignore_table=False):
    """Read-only structural + evidence scan."""
    t0 = time.time()
    r = ScanResult(disk)
    Part._n = 0
    try:
        initial_source = core.fingerprint(disk)
    except (core.SafetyError, OSError, DiskError) as e:
        initial_source = None
        r.fingerprint_error = str(e)

    cont = detect_container(disk)
    if cont:
        r.container = cont[0]
        r.block("container", "%s — %s" % (cont[0], cont[1]))

    r.mbr = parse_mbr(disk)
    r.gpt_p = read_gpt(disk, "primary")
    r.gpt_b = read_gpt(disk, "backup")

    gpt_src = None
    if r.gpt_p["valid"]:
        gpt_src = r.gpt_p
    elif r.gpt_b["valid"]:
        gpt_src = r.gpt_b
        r.add_warn("GPT اصلی خراب است ولی نسخه پشتیبان سالم است "
                   "(اقدام امن: gpt-restore-primary)")
    elif r.gpt_p["present"] or r.gpt_b["present"]:
        gpt_src = r.gpt_p if r.gpt_p["present"] else r.gpt_b
        r.add_warn("امضای GPT پیدا شد ولی CRC معتبر نیست — جدول مشکوک است.")

    if gpt_src and gpt_src.get("entries"):
        r.scheme = "GPT"
        for e in gpt_src["entries"]:
            r.parts.append(Part(e.first, e.sectors,
                                "GPT" if gpt_src is r.gpt_p else "GPT-BACKUP",
                                type_id=e.type_guid, type_name=e.type_name(),
                                name=e.name, guid=e.part_guid, attrs=e.attrs,
                                slot=e.index))
    elif r.mbr and r.mbr["present"] and not r.mbr["protective"]:
        r.scheme = "MBR"
        for e in r.mbr["entries"]:
            if e.empty or e.type in MBR_EXTENDED:
                continue
            r.parts.append(Part(e.start, e.sectors, "MBR",
                                type_id="0x%02X" % e.type,
                                type_name=e.type_name(), slot=e.slot))
        for e in r.mbr["extended_chain"]:
            r.parts.append(Part(e.start, e.sectors, e.src,
                                type_id="0x%02X" % e.type,
                                type_name=e.type_name(), slot=e.slot))
    elif r.mbr and r.mbr["protective"]:
        r.scheme = "GPT (protective MBR only — GPT tables damaged)"
        r.add_warn("Protective MBR هست ولی هیچ GPT معتبری خوانده نشد.")
    else:
        r.scheme = "RAW / no partition table"

    head = disk.read_at(0, QUICK_PROBE_BYTES)
    sf = probe_fs(head, disk.sector)
    if sf and sf["conf"] >= 0.9 and not sf["fs"].startswith("unknown"):
        r.superfloppy = sf
        if not r.parts:
            r.scheme = "Superfloppy (%s at LBA 0, no partition table)" % sf["fs"]
            r.parts.append(Part(0, sf["sectors"] or disk.sectors, "VBR@0",
                                type_name="whole-disk volume", fs=sf))

    for p in r.parts:
        if p.fs is None:
            p.fs = probe_partition_fs(disk, p)

    if not r.parts or any(p.fs is None for p in r.parts):
        r.carved.extend(sweep_common_offsets(disk, exclude=r.parts))

    if deep:
        # By default the areas already claimed by the partition table are
        # skipped. When the table itself is suspect, ignore_table searches them
        # too — a wrong table would otherwise hide the real volume inside it.
        known = [] if ignore_table else [(p.start, p.end) for p in r.all_parts]
        r.carved.extend(deep_scan(disk, step=deep_step, limit=deep_limit,
                                  time_budget=time_budget, known=known))
        r.deep_done = True
        r.deep_scope = getattr(disk, "_last_deep_scope", {"state": "UNKNOWN"})
    r.carved = dedup_parts(r.carved, [] if ignore_table else r.parts)

    # ---- evidence ---------------------------------------------------------
    for p in r.all_parts:
        p.ev = build_evidence(disk, p)
    mark_overlaps(r.all_parts)

    collect_disk_blockers(disk, r)
    collect_warnings(disk, r)
    try:
        if initial_source is not None:
            core.validate_fingerprint(disk, initial_source)
            r.source_fingerprint = safety.scan_fingerprint(sys.modules[__name__], disk, r)
    except (core.SafetyError, OSError, DiskError) as e:
        r.fingerprint_error = str(e)
        r.block("source_changed", "BLOCKED_SOURCE_CHANGED: " + str(e))
    r.elapsed = time.time() - t0
    return r


def probe_partition_fs(disk, p, big=False):
    if p.start >= disk.sectors:
        return None
    return probe_fs(disk.read_at(p.start * disk.sector,
                                 PROBE_BYTES if big else QUICK_PROBE_BYTES),
                    disk.sector)


def sweep_common_offsets(disk, exclude=()):
    """Very fast look at the offsets partitions almost always start on."""
    found = []
    ex = set(p.start for p in exclude)
    cands = sorted(set(COMMON_STARTS + [i * (MIB // disk.sector) for i in range(1, 65)]))
    for lba in cands:
        if lba in ex or lba >= disk.sectors:
            continue
        fs = probe_fs(disk.read_at(lba * disk.sector, QUICK_PROBE_BYTES), disk.sector)
        if fs and fs["conf"] >= 0.9:
            found.append(Part(lba, fs["sectors"] or max(1, disk.sectors - lba),
                              "SCAN", fs=fs, type_name="carved by signature"))
    return found


def deep_scan(disk, step=MIB, limit=0, time_budget=0, known=(), chunk=8 * MIB):
    """Sequential signature carving. Cost is dominated by read throughput."""
    found = []
    end = disk.size if not limit else min(disk.size, limit)
    t0 = time.time()
    pos = 0
    overlap = 4 * KIB
    known_ranges = list(known)
    hits = 0
    while pos < end:
        if time_budget and (time.time() - t0) > time_budget:
            warn("deep scan: time budget reached at %s" % human(pos))
            break
        n = min(chunk, end - pos)
        buf = disk.read_at(pos, n + overlap)
        if not buf:
            break
        for magic, moff, name in CARVE_SIGS:
            idx = 0
            while True:
                idx = buf.find(magic, idx)
                if idx < 0:
                    break
                cand = pos + idx - moff
                idx += 1
                if cand < 0 or cand % disk.sector:
                    continue
                lba = cand // disk.sector
                if any(a <= lba <= b for a, b in known_ranges):
                    continue
                fs = probe_fs(disk.read_at(cand, QUICK_PROBE_BYTES), disk.sector)
                if not fs or fs["conf"] < 0.9:
                    continue
                p = Part(lba, fs["sectors"] or max(1, disk.sectors - lba), "SCAN",
                         fs=fs, type_name="carved by signature")
                # --deep-step is an alignment filter. A hit that is neither on a
                # usual boundary nor backed by a mirror is almost always a boot
                # sector stored inside a file.
                if step > disk.sector and (cand % step) and lba not in COMMON_STARTS:
                    probe_ev = build_evidence(disk, p)
                    if not probe_ev.extent_verified:
                        dbg("deep: skipped unaligned %s @LBA %d" % (fs["fs"], lba))
                        continue
                found.append(p)
                known_ranges.append((p.start, p.end))
                hits += 1
        pos += n
        if not QUIET and end > 64 * MIB:
            sys.stdout.write("\r    deep scan %5.1f%%  (%s / %s)  ولوم خارج از جدول=%d   " %
                             (100.0 * pos / end, human(pos), human(end), hits))
            sys.stdout.flush()
    if not QUIET and end > 64 * MIB:
        sys.stdout.write("\r" + " " * 70 + "\r")
    disk._last_deep_scope = {"requested_bytes": end, "processed_bytes": min(pos, end),
                            "source_bytes": disk.size, "scope_complete": pos >= end,
                            "source_complete": pos >= end and end == disk.size,
                            "state": "VERIFIED" if pos >= end and end == disk.size else "UNKNOWN",
                            "time_budget_seconds": time_budget}
    return found


def dedup_parts(carved, known):
    out_ = []
    kn = [(p.start, p.end) for p in known]
    seen = set()
    for c in sorted(carved, key=lambda x: (x.start, -x.sectors)):
        if c.start in seen or any(a <= c.start <= b for a, b in kn):
            continue
        if any(o.start < c.start <= o.end for o in out_):
            continue
        seen.add(c.start)
        out_.append(c)
    return out_


def collect_disk_blockers(disk, r):
    """Disk-level conditions that forbid any synthesis of structure."""
    if r.gpt_p and r.gpt_p.get("geometry_mismatch") and r.gpt_p.get("present"):
        h = r.gpt_p["header"]
        r.block("geometry_mismatch",
                "GPT می‌گوید آخرین LBA دیسک %d است ولی دیسک واقعاً %d سکتور "
                "دارد. محتمل‌ترین علت: اندازه extent در VMDK اصلاح‌شده غلط است. "
                "تا این حل نشود همه آفست‌ها مشکوک‌اند و هیچ بازسازی مجاز نیست. "
                "تنها اقدام مجاز: gpt-fix-geometry"
                % (h["backup_lba"], disk.sectors))
    if r.mbr and r.mbr.get("out_of_range"):
        r.block("mbr_out_of_range",
                "%d ورودی MBR خارج از محدوده دیسک است — جدول احتمالاً بازمانده "
                "دیسک دیگری است یا اندازه دیسک غلط است."
                % r.mbr["out_of_range"])
    for p in r.all_parts:
        if p.ev and any(k == "overlap" for k, _ in p.ev.blockers):
            r.block("overlap", "کاندیدهای همپوشان وجود دارند؛ هیچ جدولی از روی "
                               "این مجموعه ساخته نمی‌شود.")
            break
    idx = win_disk_index_from_path(disk.path)
    if IS_WIN and idx is not None and idx in system_disk_indices():
        r.block("system_disk", T("sys_disk_block"))


def collect_warnings(disk, r):
    for p in r.all_parts:
        if not p.ev:
            continue
        for k, why in p.ev.blockers:
            r.add_warn("پارتیشن #%d [%s]: %s" % (p.num, k, why))
        if p.fs and p.fs["fs"] == "ReFS":
            ver = (p.fs.get("fields") or {}).get("version")
            r.add_warn("پارتیشن #%d فایل‌سیستم ReFS دارد (نسخه %s). این ابزار "
                       "هیچ ترمیم سطح-سکتوری روی ReFS انجام نمی‌دهد؛ مسیر درست "
                       "refsutil salvage است (--action refsutil). توجه: "
                       "refsutil فقط ReFS تا سقف نسخه‌ای که با همان build "
                       "ویندوز آمده را می‌خواند — نسخه‌های جدیدتر (٣.١٠ به "
                       "بالا) را حتی روی ولوم سالم رد می‌کند و پیام آن با "
                       "خرابی فایل‌سیستم اشتباه گرفته می‌شود."
                       % (p.num, ver or "?"))
        if p.fs is None and p.sectors and not type_expects_no_fs(p):
            r.add_warn("پارتیشن #%d در جدول هست ولی Boot Sector معتبری ندارد "
                       "(RAW) — با --triage عمق خرابی را بسنج." % p.num)
        if p.type_id in ("0x42",) or str(p.type_id).upper() in (
                "5808C8AA-7E8F-42E0-85D2-E1E90434CFB3",
                "AF9B60A0-1431-4F62-BC68-3311714A69AD"):
            r.add_warn("پارتیشن #%d متعلق به دیسک داینامیک (LDM) است؛ بازسازی "
                       "جدول، ولوم منطقی را برنمی‌گرداند." % p.num)
    if r.gpt_p and r.gpt_b:
        if r.gpt_p["valid"] and not r.gpt_b["valid"]:
            r.add_warn("GPT پشتیبان خراب/غایب است (اقدام امن: gpt-restore-backup)")
    if r.scheme.startswith("RAW") and not r.carved:
        r.add_warn("نه جدول پارتیشن سالم است نه امضای فایل‌سیستمی پیدا شد. "
                   "با --deep --deep-step 512 دوباره اسکن کن.")


# =============================================================================
# SECTION 9b — Volume forensics  (--triage)
# =============================================================================
# When a partition exists in the table but has no filesystem at its start, the
# question that decides everything is: how deep does the damage go? A wiped
# boot sector and a volume whose first 100 GiB were overwritten look identical
# from LBA 0. These routines answer it in one pass, read-only.
# =============================================================================

FORENSIC_SIGS = [
    (b"SUPB", "ReFS superblock"),
    (b"CHKP", "ReFS checkpoint"),
    (b"FSRS", "ReFS structure id"),
    (b"NTFS    ", "NTFS boot sector"),
    (b"EXFAT   ", "exFAT boot sector"),
    (b"FAT32   ", "FAT32 boot sector"),
    (b"-FVE-FS-", "BitLocker header"),
    (b"XFSB", "XFS superblock"),
    (b"_BHRfS_M", "Btrfs superblock"),
]
REFS_STRUCT_SIGS = (b"SUPB", b"CHKP", b"FSRS")


def entropy(buf, sample=4096):
    """Shannon entropy in bits per byte, measured on a bounded subsample."""
    b = buf[:sample]
    if not b:
        return 0.0
    n = len(b)
    e = 0.0
    for v in range(256):
        c = b.count(v)
        if c:
            pr = c / n
            e -= pr * math.log(pr, 2)
    return e


def parse_refs_header(sec):
    """Read a sector as a ReFS volume header.

    'FSRS' is located by search, not at a fixed offset: published layouts
    disagree about the size of the MustBeZero field, and a real disk showed the
    identifier at 0x10 rather than the 0x0F some references give. Everything
    else is read relative to where FSRS actually is.
    """
    if len(sec) < 64 or sec[3:7] != b"ReFS":
        return None
    idx = sec.find(b"FSRS", 7, 0x30)
    if idx < 0:
        return None
    try:
        h = {
            "fsrs_offset": idx,
            "length": u16(sec, idx + 4),
            "checksum": u16(sec, idx + 6),
            "num_sectors": u64(sec, idx + 8),
            "bytes_per_sector": u32(sec, idx + 16),
            "sectors_per_cluster": u32(sec, idx + 20),
            "major": sec[idx + 24],
            "minor": sec[idx + 25],
        }
    except Exception:
        return None
    h["sane"] = (h["bytes_per_sector"] in (512, 1024, 2048, 4096)
                 and 0 < h["num_sectors"] < (1 << 48)
                 and h["major"] in (1, 2, 3))
    return h


def find_refs_header_copy(disk, start_lba, declared_sectors):
    """A ReFS volume keeps a copy of its header in its last sector."""
    if declared_sectors <= 1:
        return None
    lba = start_lba + declared_sectors - 1
    if lba <= start_lba or lba >= disk.sectors:
        return None
    sec = disk.read_at(lba * disk.sector, disk.sector)
    h = parse_refs_header(sec)
    if h and h["sane"]:
        return {"lba": lba, "header": h, "raw": sec}
    return None


def scan_refs_header_near_end(disk, p, window_mib=512):
    """Find a ReFS volume header copy without knowing the volume length.

    Used when the primary header is gone: walk backwards from the end of the
    partition looking for a sector shaped like a ReFS volume header, then check
    whether its declared length lands its own position at start+len-1.
    """
    s = disk.sector
    end = min((p.end + 1) * s, disk.size)
    span = min(window_mib * MIB, p.sectors * s)
    pos = end - span
    best = None
    while pos < end:
        n = min(8 * MIB, end - pos)
        buf = disk.read_at(pos, n + 64)
        if not buf:
            break
        i = 0
        while True:
            i = buf.find(b"FSRS", i)
            if i < 0:
                break
            sec_off = ((pos + i) // s) * s
            sec = disk.read_at(sec_off, s)
            h = parse_refs_header(sec)
            i += 1
            if not (h and h["sane"]):
                continue
            lba = sec_off // s
            consistent = (p.start + h["num_sectors"] - 1 == lba)
            cand = {"lba": lba, "header": h, "self_consistent": consistent,
                    "raw": sec}
            if consistent:
                return cand
            best = best or cand
        pos += n
    return best


def find_structures(disk, first_byte, last_byte, max_hits=8, progress=None):
    """Signature sweep over a byte range."""
    hits = {}
    pos = first_byte
    total = max(1, last_byte - first_byte)
    empty = True
    while pos < last_byte:
        n = min(8 * MIB, last_byte - pos)
        buf = disk.read_at(pos, n + 64)
        if not buf:
            break
        if empty and any(buf):
            empty = False
        for sig, name in FORENSIC_SIGS:
            i = 0
            while True:
                i = buf.find(sig, i)
                if i < 0:
                    break
                hits.setdefault(name, [])
                if len(hits[name]) < max_hits:
                    hits[name].append(pos + i)
                i += 1
        pos += n
        if progress and not QUIET:
            sys.stdout.write("\r    %s %5.1f%%   " % (progress, 100.0 * (pos - first_byte) / total))
            sys.stdout.flush()
    if progress and not QUIET:
        sys.stdout.write("\r" + " " * 40 + "\r")
    return hits, empty


REGION_CHAR = {"zero": ".", "refs": "R", "other-fs": "F", "high-entropy": "#",
               "data": "d", "sparse": "-", "unreadable": "X"}


def classify_region(buf):
    if not buf:
        return "unreadable", 0.0
    if not any(buf):
        return "zero", 0.0
    for sig in REFS_STRUCT_SIGS:
        if sig in buf:
            return "refs", entropy(buf)
    for sig, _ in FORENSIC_SIGS:
        if sig in REFS_STRUCT_SIGS:
            continue
        if sig in buf:
            return "other-fs", entropy(buf)
    e = entropy(buf)
    if e >= 7.5:
        return "high-entropy", e
    if e >= 4.0:
        return "data", e
    return "sparse", e


def damage_map(disk, p, samples=320, sample_kib=64):
    """Sample the partition evenly and classify each sample."""
    s = disk.sector
    p0, p1 = p.start * s, (p.end + 1) * s
    span = p1 - p0
    n = max(16, samples)
    step = max(s, span // n)
    ssize = sample_kib * 1024
    rows = []
    counts = {}
    first_refs = None
    last_foreign = None
    for i in range(n):
        off = p0 + i * step
        if off >= p1:
            break
        buf = disk.read_at(off, ssize)
        kind, ent = classify_region(buf)
        counts[kind] = counts.get(kind, 0) + 1
        rows.append({"lba": off // s, "kind": kind, "entropy": round(ent, 2)})
        if kind == "refs" and first_refs is None:
            first_refs = off
        if kind in ("high-entropy", "other-fs"):
            last_foreign = off
        if not QUIET and (i % 16 == 0):
            sys.stdout.write("\r    damage map %5.1f%%   " % (100.0 * i / n))
            sys.stdout.flush()
    if not QUIET:
        sys.stdout.write("\r" + " " * 40 + "\r")
    return {"rows": rows, "counts": counts, "step": step, "samples": len(rows),
            "first_refs_lba": (first_refs // s) if first_refs else None,
            "last_foreign_lba": (last_foreign // s) if last_foreign else None}


def _print_map_rows(rows, width=64):
    line = []
    for i, row in enumerate(rows):
        line.append(REGION_CHAR.get(row["kind"], "?"))
        if len(line) == width:
            out("      %s   LBA %d" % ("".join(line), rows[i - width + 1]["lba"]))
            line = []
    if line:
        out("      %s   LBA %d"
            % ("".join(line), rows[len(rows) - len(line)]["lba"]))


def head_map(disk, p, gib=8, samples=128):
    """Dense sampling of the first few GiB, where a targeted wipe lands."""
    s = disk.sector
    p0 = p.start * s
    span = min(gib * 1024 * MIB, p.sectors * s)
    step = max(s, span // max(8, samples))
    rows, counts = [], {}
    n = int(span // step)
    for i in range(n):
        off = p0 + i * step
        kind, ent = classify_region(disk.read_at(off, 64 * KIB))
        counts[kind] = counts.get(kind, 0) + 1
        rows.append({"lba": off // s, "kind": kind, "entropy": round(ent, 2)})
    return {"rows": rows, "counts": counts, "step": step, "span": span,
            "samples": len(rows)}


def dump_range(disk, start_lba, count, out_path, strings_min=6,
               filter_noise=True):
    """Copy a raw sector range out to a file, read-only.

    Used to lift a small structure — a .vbm, a boot sector, a metadata node —
    out of a volume whose filesystem can no longer locate it. Also extracts the
    printable strings it contains, which is usually the reason you wanted the
    bytes in the first place.
    """
    safety.ensure_destination(sys.modules[__name__], disk, out_path)
    if count <= 0:
        raise DiskError("count must be positive")
    if start_lba < 0 or start_lba >= disk.sectors:
        raise DiskError("start LBA %d is outside the disk (last LBA %d)"
                        % (start_lba, disk.sectors - 1))
    if start_lba + count > disk.sectors:
        count = disk.sectors - start_lba
        warn("محدوده تا انتهای دیسک کوتاه شد: %d سکتور" % count)

    total = count * disk.sector
    written = 0
    bad = 0
    t0 = time.time()
    with open(out_path, "xb") as f:
        pos = 0
        while pos < total:
            n = min(8 * MIB, total - pos)
            data = _read_retry(disk, start_lba * disk.sector + pos, n, 3)
            if data is None or len(data) < n:
                bad += n - (len(data) if data else 0)
                data = (data or b"") + _fill_block("pat", n - (len(data) if data else 0))
            f.write(data)
            pos += n
            written += n
    res = {"start_lba": start_lba, "sectors": count, "bytes": written,
           "unreadable_bytes": bad, "path": out_path,
           "elapsed": round(time.time() - t0, 1)}
    ok("%s نوشته شد از LBA %d (%d سکتور)%s"
       % (human(written), start_lba, count,
          "، %s غیرقابل خواندن" % human(bad) if bad else ""))
    with open(out_path, "rb") as f:
        blob = f.read(min(written, 64 * MIB))
    res["strings"] = extract_strings(blob, strings_min,
                                     filter_noise=filter_noise)
    res["noise_filtered"] = bool(filter_noise)
    return res


# A run of printable bytes is not the same thing as a string someone wrote.
# Compressed and encrypted data produces short printable runs constantly, so a
# raw dump of a backup file drowns real filenames in noise. These heuristics
# score a run on how much it looks like deliberate text.
_TEXTY = re.compile(r"^[A-Za-z0-9 ._\-()\[\]{}:;,/\\@#'\"+=!?*&%$~|<>]+$")
_ALPHA_RUN = re.compile(r"[A-Za-z]+")
_CAMEL_SPLIT = re.compile(r"(?<=[a-z])(?=[A-Z])")
_FILE_EXT = re.compile(r"[A-Za-z0-9)\]]\.[a-z0-9]{2,4}$")


def _camel_tokens(s):
    """Split alphabetic runs on lowercase->uppercase boundaries.

    Keeps 'Noavaran' whole and 'FsAwareMeta' as Fs/Aware/Meta, while random
    case flipping — the signature of compressed bytes that happen to be
    printable — shatters into one- and two-letter fragments.
    """
    toks = []
    for run in _ALPHA_RUN.findall(s):
        toks.extend(t for t in _CAMEL_SPLIT.split(run) if t)
    return toks


def looks_like_text(s):
    """Is this printable run plausibly real text rather than compression noise?

    Two independent ways to qualify: it contains a genuine word (a CamelCase
    token of four or more letters), or it ends in a lowercase file extension.
    Compressed data almost never produces either, while filenames and paths
    reliably produce at least one.
    """
    if not s or not _TEXTY.match(s):
        return False
    alnum = sum(1 for ch in s if ch.isalnum())
    if alnum / float(len(s)) < 0.6:
        return False
    toks = _camel_tokens(s)
    if not toks:
        return False
    if max(len(t) for t in toks) >= 4:
        return True
    return bool(_FILE_EXT.search(s))


def extract_strings(blob, minimum=6, max_out=400, filter_noise=True):
    """Printable ASCII and UTF-16LE runs, in the order they appear.

    With filter_noise (the default) only runs that look like deliberate text
    are returned; set it False to see every printable run, noise included.
    """
    out_list = []
    seen = set()

    def add(s):
        s = s.strip()
        if len(s) < minimum or s in seen:
            return
        if filter_noise and not looks_like_text(s):
            return
        seen.add(s)
        out_list.append(s)

    def scan_ascii():
        cur = []
        for b in blob:
            if 32 <= b < 127:
                cur.append(chr(b))
                continue
            if len(cur) >= minimum:
                add("".join(cur))
            cur = []
            if len(out_list) >= max_out:
                return
        if len(cur) >= minimum:
            add("".join(cur))

    def scan_utf16():
        cur = []
        for i in range(0, len(blob) - 1, 2):
            lo, hi = blob[i], blob[i + 1]
            if hi == 0 and 32 <= lo < 127:
                cur.append(chr(lo))
                continue
            if len(cur) >= minimum:
                add("".join(cur))
            cur = []
            if len(out_list) >= max_out:
                return
        if len(cur) >= minimum:
            add("".join(cur))

    scan_ascii()
    scan_utf16()
    return out_list[:max_out]


def print_dump_range(res):
    out("")
    out(C.w(C.BOLD, " استخراج محدوده خام"))
    out("   از LBA   : %d  (%d سکتور، %s)"
        % (res["start_lba"], res["sectors"], human(res["bytes"])))
    out("   فایل     : %s" % res["path"])
    if res["unreadable_bytes"]:
        out("   " + C.w(C.YELLOW, "%s غیرقابل خواندن بود و با الگو پر شد"
                        % human(res["unreadable_bytes"])))
    s = res.get("strings") or []
    if not s:
        out("   هیچ رشته خوانایی در این محدوده نیست."
            + ("  (فیلتر نویز روشن است؛ با --dump-raw-strings همه را ببین)"
               if res.get("noise_filtered") else ""))
        return
    out("   %d رشته%s:" % (len(s), " (نویز فشرده فیلتر شد)"
                          if res.get("noise_filtered") else " خام"))
    for line in s[:120]:
        out("      " + line[:160])
    if len(s) > 120:
        out("      ... %d رشته دیگر (همه در فایل خروجی هستند)" % (len(s) - 120))


# =============================================================================
# Veeam .vbm metadata locator + convenience carving  (v1.8)
# =============================================================================
# Veeam's .vbk/.vib storage format is proprietary and undocumented — Veeam
# support has explicitly declined to publish its header layout even to people
# asking in their own forum. There is no reliable magic number to search for.
#
# The .vbm backup-chain metadata file, however, IS documented (published
# third-party research: Synacktiv, "Using Veeam metadata for efficient
# extraction of Backup artefacts", Feb 2024). It is plain XML when the backup
# is unencrypted, small (KB-to-low-MB), and its <Storage> element gives the
# exact original filename and the exact BackupSize in bytes of the .vbk/.vib
# it describes. That is real, sourced ground truth — unlike guessing a VBK
# start offset from entropy, which is a heuristic with no guarantee.
# =============================================================================

VBM_ANCHOR = b"<BackupMeta"
VBM_FIELD_PATTERNS = {
    "FilePath": re.compile(rb'FilePath="([^"]*)"'),
    "BackupSize": re.compile(rb'<BackupSize>(\d+)</BackupSize>'),
    "DataSize": re.compile(rb'<DataSize>(\d+)</DataSize>'),
    "EncryptionState": re.compile(rb'EncryptionState="(\d+)"'),
    "CreationTimeUtc": re.compile(rb'CreationTimeUtc="([^"]*)"'),
    "JobName": re.compile(rb'JobName="([^"]*)"'),
    "VmName": re.compile(rb'VmName="([^"]*)"'),
    "DisplayName": re.compile(rb'DisplayName="([^"]*)"'),
    "MetaFileName": re.compile(rb'MetaFileName="([^"]*)"'),
}


def parse_vbm_fields(blob):
    """Pull the handful of documented, useful fields out of a .vbm XML blob.

    This is deliberately not a real XML parser: the blob may be truncated at
    either end (we don't know the file's exact boundaries going in), so a
    strict parser would just fail. Regex extraction degrades gracefully and
    returns whatever fields it can find, with each field taken from every
    match in the blob (a chain can have several <Storage> elements — one per
    restore point — so BackupSize/FilePath may repeat).
    """
    out = {}
    for name, pat in VBM_FIELD_PATTERNS.items():
        vals = []
        for m in pat.finditer(blob):
            try:
                v = m.group(1).decode("utf-8", "replace")
            except Exception:
                continue
            if v not in vals:
                vals.append(v)
        if vals:
            out[name] = vals
    return out


def find_vbm_metadata(disk, limit=0, window=512 * KIB, max_hits=20, chunk=64 * MIB):
    """Search the raw disk for .vbm XML content (not just its directory entry).

    Anchors on the literal, unique root tag "<BackupMeta" — case-sensitive
    ASCII, since the .vbm is a plain UTF-8/ASCII XML file, not filesystem
    metadata (which is why this is a different search than --find-name). For
    each hit, reads `window` bytes forward and extracts the documented fields.
    Read-only.
    """
    end = disk.size if not limit else min(disk.size, limit)
    hits = []
    pos = 0
    overlap = len(VBM_ANCHOR)
    t0 = time.time()
    short_read = False
    while pos < end and len(hits) < max_hits:
        n = min(chunk, end - pos)
        buf = disk.read_at(pos, n + overlap)
        if not buf:
            break
        short_read = len(buf) < n
        i = 0
        while len(hits) < max_hits:
            i = buf.find(VBM_ANCHOR, i)
            if i < 0:
                break
            # "<BackupMeta" is also a prefix of "<BackupMetaInfo>", a
            # different, non-root element. Only accept the exact root tag,
            # i.e. the anchor immediately followed by '>' or whitespace.
            nxt = buf[i + len(VBM_ANCHOR):i + len(VBM_ANCHOR) + 1]
            if nxt not in (b">", b" ", b"\t", b"\r", b"\n"):
                i += 1
                continue
            off = pos + i
            blob = disk.read_at(off, window)
            fields = parse_vbm_fields(blob)
            hits.append({"offset": off, "lba": off // disk.sector,
                        "window": window, "fields": fields})
            i += 1
        pos += min(n, len(buf))
        if short_read:
            break
        if not QUIET:
            sys.stdout.write("\r    searching %5.1f%%  (%s / %s)  hits=%d   "
                             % (100.0 * pos / end, human(pos), human(end), len(hits)))
            sys.stdout.flush()
    if not QUIET:
        sys.stdout.write("\r" + " " * 72 + "\r")
    return {"hits": hits, "scanned": min(pos, end),
            "elapsed": round(time.time() - t0, 1), "scope_bytes": end,
            "source_bytes": disk.size, "truncated": len(hits) >= max_hits,
            "scope_complete": pos >= end and len(hits) < max_hits and not short_read,
            "source_complete": pos >= end and end == disk.size and len(hits) < max_hits and not short_read}


def print_find_vbm(res):
    out("")
    out(C.w(C.BOLD, " جستجوی متادیتای .vbm (تگ XML، نه ورودی دایرکتوری)"))
    out("   خوانده  : %s در %.0f ثانیه" % (human(res["scanned"]), res["elapsed"]))
    if not res["hits"]:
        out("   " + C.w(C.YELLOW, "هیچ .vbm خوانا پیدا نشد."))
        out("   یا رمزنگاری شده، یا در ناحیه بازنویسی‌شده افتاده، یا سقف "
            "--find-vbm-max-hits زودتر پر شد.")
        return
    out("   " + C.w(C.GREEN, "%d مورد" % len(res["hits"])))
    for h in res["hits"]:
        out("")
        out("   LBA %d  (offset 0x%X)" % (h["lba"], h["offset"]))
        f = h["fields"]
        if not f:
            out(C.w(C.YELLOW, "      هیچ فیلد شناخته‌شده‌ای در این پنجره پیدا نشد؛ "
                              "شاید window کوچک بوده یا رمزنگاری شده."))
            continue
        enc = f.get("EncryptionState")
        if enc and enc[0] not in ("0",):
            out(C.w(C.RED, "      EncryptionState=%s — این بکاپ رمزنگاری شده؛ "
                          "بدون کلید قابل استخراج نیست." % enc[0]))
        for name in ("FilePath", "BackupSize", "DataSize", "VmName",
                    "DisplayName", "JobName", "CreationTimeUtc", "MetaFileName"):
            vals = f.get(name)
            if not vals:
                continue
            if name == "BackupSize":
                for v in vals:
                    try:
                        out("      BackupSize      : %s (%s)" % (v, human(int(v))))
                    except Exception:
                        out("      BackupSize      : %s" % v)
            elif name == "DataSize":
                for v in vals:
                    try:
                        out("      DataSize        : %s (%s)" % (v, human(int(v))))
                    except Exception:
                        out("      DataSize        : %s" % v)
            else:
                for v in vals:
                    out("      %-15s : %s" % (name, v))


def locate_vbk_start(disk, center_lba, size_bytes, align_bytes=65536,
                     radius_gib=2.0, sample_bytes=8192, max_candidates=4000,
                     keep_top=20):
    """Find the precise start offset of a known-size Veeam storage file.

    We cannot rely on a documented VBK magic number (Veeam does not publish
    one). What we DO have is the exact byte size from the .vbm's BackupSize
    field, and the fact that Veeam aligns its internal blocks to
    BlockAlignmentSize (typically 65536 bytes, taken straight from the .vbm).

    This scans candidate start offsets on that alignment, within a radius of
    the given center LBA, and scores each one on whether it looks like a real
    file boundary: content just before the candidate start should look
    different from content just after it (a transition), the run starting at
    the candidate should still look like file content `size_bytes` later
    (i.e. the file's declared length is honoured), and content right after
    the computed end should again look different (the next file/metadata).

    This is a heuristic, not a certainty -- there is no documented format to
    verify against. It narrows a multi-gigabyte guess down to a short list of
    strong candidates, each cheap enough (a few KB of reads) to try in
    practice instead of carving tens or hundreds of gigabytes per attempt.
    Read-only.
    """
    s = disk.sector
    align_sectors = max(1, align_bytes // s)
    radius_sectors = int(radius_gib * 1024 * MIB) // s
    radius_sectors = (radius_sectors // align_sectors) * align_sectors
    size_sectors = (size_bytes + s - 1) // s

    lo = max(0, center_lba - radius_sectors)
    hi = min(disk.sectors - size_sectors - 1, center_lba + radius_sectors)
    lo = (lo // align_sectors) * align_sectors
    if hi <= lo:
        return {"candidates": [], "scanned": 0, "reason": "search window is empty"}

    step = align_sectors
    total_steps = (hi - lo) // step + 1
    if total_steps > max_candidates:
        step = ((hi - lo) // max_candidates // align_sectors + 1) * align_sectors

    results = []
    t0 = time.time()
    n = 0
    for start in range(lo, hi + 1, step):
        n += 1
        end = start + size_sectors
        before = disk.read_at(max(0, start * s - sample_bytes), sample_bytes)
        at_start = disk.read_at(start * s, sample_bytes)
        at_end_inside = disk.read_at(max(start * s, end * s - sample_bytes), sample_bytes)
        after = disk.read_at(end * s, sample_bytes)
        if not (before and at_start and at_end_inside and after):
            continue
        k_before, e_before = classify_region(before)
        k_start, e_start = classify_region(at_start)
        k_end, e_end = classify_region(at_end_inside)
        k_after, e_after = classify_region(after)

        content_like = k_start in ("high-entropy", "data") and \
                       k_end in ("high-entropy", "data")
        if not content_like:
            continue

        boundary_before = (k_before != k_start) or (abs(e_before - e_start) > 1.5)
        boundary_after = (k_after != k_end) or (abs(e_after - e_end) > 1.5)
        score = 0.0
        score += 2.0 if boundary_before else 0.0
        score += 2.0 if boundary_after else 0.0
        score += 1.0 if k_start == "high-entropy" else 0.3
        score += 1.0 if k_end == "high-entropy" else 0.3
        if score <= 0:
            continue
        results.append({
            "start_lba": start, "end_lba": end,
            "score": round(score, 2),
            "before": {"kind": k_before, "entropy": round(e_before, 2)},
            "at_start": {"kind": k_start, "entropy": round(e_start, 2)},
            "at_end": {"kind": k_end, "entropy": round(e_end, 2)},
            "after": {"kind": k_after, "entropy": round(e_after, 2)},
        })
        if not QUIET and n % 200 == 0:
            sys.stdout.write("\r    probing %5.1f%%  candidates=%d  hits=%d   "
                             % (100.0 * (start - lo) / max(1, hi - lo), n, len(results)))
            sys.stdout.flush()
    if not QUIET:
        sys.stdout.write("\r" + " " * 72 + "\r")
    results.sort(key=lambda r: -r["score"])
    # keep_top must be able to serve --locate-verify-top-n, which can ask for
    # far more than the 20 a human would want to read on screen. A bug here
    # once silently capped verification at 20 regardless of what was asked.
    return {"candidates": results[:max(keep_top, 1)], "scanned_candidates": n,
           "elapsed": round(time.time() - t0, 1), "align_bytes": align_bytes,
           "size_bytes": size_bytes}


def verify_vbk_candidate(disk, start_lba, needle, probe_bytes=8 * MIB):
    """Read a small probe from a candidate start and check for a name.

    Case-insensitive, checked against both raw bytes and the string-extracted
    view so the match works whether the name appears as plain ASCII (e.g.
    inside an embedded VMDK descriptor) or is split across a compressed
    boundary. This is a cheap, decisive test: reads a few MB, not gigabytes.
    """
    buf = disk.read_at(start_lba * disk.sector, probe_bytes)
    if not buf:
        return {"hit": False, "context": None}
    low = buf.lower()
    nlow = needle.lower().encode("latin1", "replace")
    idx = low.find(nlow)
    if idx < 0:
        return {"hit": False, "context": None}
    ctx = buf[max(0, idx - 60):idx + len(needle) + 120]
    text = "".join(ch if 32 <= b < 127 and (ch := chr(b)) else "."
                   for b in ctx)
    return {"hit": True, "offset_in_probe": idx, "context": text}


def locate_vbk_start_verified(disk, center_lba, size_bytes, needle,
                              align_bytes=65536, radius_gib=2.0,
                              sample_bytes=8192, max_candidates=4000,
                              verify_top_n=40, probe_bytes=8 * MIB):
    """Rank candidates by boundary score, then verify the top N by content.

    The entropy/alignment score (locate_vbk_start) narrows a multi-gigabyte
    guess to a short list cheaply, but entropy alone cannot distinguish "the
    right file" from "some other compressed file with a similarly-shaped
    boundary" -- which is exactly what kept happening on this dense
    repository. This adds a second, decisive pass: read a few MB from each of
    the top-scoring candidates and check whether the target name actually
    appears near the start, the way it did for every candidate that turned
    out correct in this session (a VMDK descriptor block near byte 0).
    Read-only throughout.
    """
    ranked = locate_vbk_start(disk, center_lba, size_bytes,
                              align_bytes=align_bytes, radius_gib=radius_gib,
                              sample_bytes=sample_bytes,
                              max_candidates=max_candidates,
                              keep_top=max(verify_top_n, 20))
    cands = ranked.get("candidates") or []
    verified = []
    checked = 0
    t0 = time.time()
    for c in cands[:verify_top_n]:
        checked += 1
        v = verify_vbk_candidate(disk, c["start_lba"], needle, probe_bytes)
        entry = dict(c)
        entry["verified"] = v["hit"]
        entry["match_context"] = v.get("context")
        verified.append(entry)
        if not QUIET:
            sys.stdout.write("\r    verifying %d/%d  hits=%d   "
                             % (checked, min(verify_top_n, len(cands)),
                                sum(1 for x in verified if x["verified"])))
            sys.stdout.flush()
    if not QUIET:
        sys.stdout.write("\r" + " " * 60 + "\r")
    verified.sort(key=lambda r: (not r["verified"], -r["score"]))
    ranked["candidates"] = verified
    ranked["needle"] = needle
    ranked["verify_checked"] = checked
    ranked["verify_elapsed"] = round(time.time() - t0, 1)
    ranked["verify_hits"] = sum(1 for x in verified if x["verified"])
    return ranked


def print_locate_vbk_verified(res):
    out("")
    out(C.w(C.BOLD, " یافتن و تایید نقطه شروع دقیق"))
    out("   %d کاندید امتیازدهی شد، %d تای برتر با محتوا تایید شد "
        "(%.1f ثانیه)، %d مورد تایید شد"
        % (res.get("scanned_candidates", 0), res.get("verify_checked", 0),
           res.get("verify_elapsed", 0), res.get("verify_hits", 0)))
    cands = res.get("candidates") or []
    if not cands:
        out("   " + C.w(C.YELLOW, "هیچ کاندیدی حتی برای امتیازدهی پیدا نشد."))
        return
    hits = [c for c in cands if c.get("verified")]
    if hits:
        out("")
        out("   " + C.w(C.GREEN, "کاندیدهای تاییدشده (نام مورد نظر واقعاً در همان "
                                 "چند مگابایت اول پیدا شد):"))
        for i, c in enumerate(hits, 1):
            out("   ★ %2d) LBA %-12d امتیاز %.1f" % (i, c["start_lba"], c["score"]))
            if c.get("match_context"):
                out("        %s" % c["match_context"][:150])
        best = hits[0]
        size_sectors = (res["size_bytes"] + 511) // 512
        out("")
        out("   برای استخراج:")
        out("      --dump-range %d:%d --dump-out FILE" % (best["start_lba"], size_sectors))
    else:
        out("")
        out("   " + C.w(C.YELLOW, "هیچ‌کدام از کاندیدهای برتر تایید نشدند."))
        out("   یعنی نام مورد نظر در همان چند مگابایت اول هیچ‌کدام از این "
            "کاندیدها نبود. گزینه‌ها:")
        out("      - شعاع را بزرگ‌تر یا کوچک‌تر کن (--locate-radius-gib)")
        out("      - verify-top-n را بیشتر کن تا کاندیدهای بیشتری چک شود")
        out("      - probe-bytes را بزرگ‌تر کن، شاید نام کمی دورتر از byte 0 باشد")
        out("   کاندیدهای امتیازدار (بدون تایید محتوا) برای مرجع:")
        for i, c in enumerate(cands[:5], 1):
            out("      %d) LBA %-12d امتیاز %.1f" % (i, c["start_lba"], c["score"]))


def print_locate_vbk(res):
    out("")
    out(C.w(C.BOLD, " یافتن نقطه شروع دقیق (اندازه دقیق + تراز بلوک)"))
    out("   %d کاندید بررسی شد در %.1f ثانیه (تراز %s)"
        % (res["scanned_candidates"], res["elapsed"], human(res.get("align_bytes", 0))))
    cands = res.get("candidates") or []
    if not cands:
        out("   " + C.w(C.YELLOW, "هیچ کاندید قابل‌قبولی پیدا نشد."))
        out("   شعاع جستجو (--locate-radius-gib) را بزرگ‌تر کن یا تراز را عوض کن.")
        return
    out("   بهترین کاندیدها (امتیاز بالاتر = مرز واضح‌تر قبل و بعد):")
    out("")
    for i, c in enumerate(cands[:10], 1):
        mark = C.w(C.GREEN, "★") if i == 1 else " "
        out("   %s %2d) LBA %-12d  امتیاز %.1f" % (mark, i, c["start_lba"], c["score"]))
        out("        قبل از شروع : %-14s entropy=%.2f" % (c["before"]["kind"], c["before"]["entropy"]))
        out("        شروع فایل   : %-14s entropy=%.2f" % (c["at_start"]["kind"], c["at_start"]["entropy"]))
        out("        پایان فایل  : %-14s entropy=%.2f" % (c["at_end"]["kind"], c["at_end"]["entropy"]))
        out("        بعد از پایان: %-14s entropy=%.2f" % (c["after"]["kind"], c["after"]["entropy"]))
    out("")
    best = cands[0]
    size_sectors = (res["size_bytes"] + 511) // 512
    out("   برای استخراج بهترین کاندید:")
    out("      --dump-range %d:%d --dump-out FILE" % (best["start_lba"], size_sectors))


def carve_vbk(disk, center_lba, margin_gib, out_path, strings_min=20):
    """Extract a generous, contiguous window of raw sectors around a known
    content offset, for handing to Veeam Extract Utility / Backup & Replication
    as a candidate .vbk. Convenience wrapper over dump_range that computes the
    start/count from a center point and a margin instead of exact LBAs, since
    the true start of a VBK cannot currently be located with certainty (see
    the module docstring above).
    """
    s = disk.sector
    margin_sectors = int(margin_gib * 1024 * MIB // s)
    start = center_lba - margin_sectors
    clamped_head = start < 0
    if clamped_head:
        start = 0
    count = margin_sectors * 2
    if clamped_head:
        count = (center_lba + margin_sectors) - start
    if clamped_head:
        warn("محدوده تا ابتدای دیسک کوتاه شد.")
    res = dump_range(disk, start, count, out_path, strings_min, filter_noise=True)
    res["center_lba"] = center_lba
    res["margin_gib"] = margin_gib
    return res

def find_name(disk, needle, limit=0, max_hits=50, chunk=64 * MIB):
    """Search the raw disk for a filename, independent of any filesystem.

    Filenames live in filesystem metadata as UTF-16LE on NTFS/ReFS/exFAT, so a
    name can still be found byte-for-byte even when the structures that would
    normally locate the file are destroyed. Both UTF-16LE and ASCII forms are
    searched, case-insensitively, because the point is to answer "was this file
    ever on this volume" when nothing else can.
    """
    pats = []
    for enc, label in (("utf-16-le", "UTF-16"), ("ascii", "ASCII")):
        try:
            lo = needle.lower().encode(enc)
            up = needle.upper().encode(enc)
        except Exception:
            continue
        pats.append((lo, label, enc))
        if up != lo:
            pats.append((up, label, enc))
        mixed = needle.encode(enc)
        if mixed not in (lo, up):
            pats.append((mixed, label, enc))

    end = disk.size if not limit else min(disk.size, limit)
    hits = []
    pos = 0
    overlap = 512
    t0 = time.time()
    short_read = False
    while pos < end and len(hits) < max_hits:
        n = min(chunk, end - pos)
        buf = disk.read_at(pos, n + overlap)
        if not buf:
            break
        short_read = len(buf) < n
        low = buf.lower()
        for pat, label, enc in pats:
            i = 0
            pl = pat.lower()
            while len(hits) < max_hits:
                i = low.find(pl, i)
                if i < 0:
                    break
                off = pos + i
                if not any(abs(off - h["offset"]) < 4 for h in hits):
                    ctx = buf[max(0, i - 96):i + len(pat) + 96]
                    try:
                        text = ctx.decode(enc, "replace") if enc == "utf-16-le" \
                            else ctx.decode("latin1", "replace")
                    except Exception:
                        text = ""
                    text = "".join(ch if ch.isprintable() else "." for ch in text)
                    hits.append({"offset": off, "lba": off // disk.sector,
                                 "encoding": label, "context": text.strip()})
                i += 1
        pos += min(n, len(buf))
        if short_read:
            break
        if not QUIET:
            sys.stdout.write("\r    searching %5.1f%%  (%s / %s)  hits=%d   "
                             % (100.0 * pos / end, human(pos), human(end), len(hits)))
            sys.stdout.flush()
    if not QUIET:
        sys.stdout.write("\r" + " " * 72 + "\r")
    return {"needle": needle, "hits": hits, "scanned": min(pos, end),
            "elapsed": round(time.time() - t0, 1),
            "truncated": len(hits) >= max_hits,
            "scope_bytes": end, "source_bytes": disk.size,
            "scope_complete": pos >= end and len(hits) < max_hits and not short_read,
            "source_complete": end == disk.size and pos >= end and len(hits) < max_hits and not short_read,
            "absence_state": "VERIFIED" if not hits and end == disk.size and pos >= end and not short_read else "UNKNOWN"}


def print_find_name(res, disk):
    out("")
    out(C.w(C.BOLD, " جستجوی نام روی دیسک خام"))
    out("   عبارت   : %s" % res["needle"])
    out("   خوانده  : %s در %.0f ثانیه" % (human(res["scanned"]), res["elapsed"]))
    if not res["hits"]:
        out("   " + C.w(C.YELLOW, "هیچ موردی پیدا نشد."))
        out("   نبودن نتیجه فقط به محدودهٔ واقعاً بررسی‌شده مربوط است. توجه: اگر")
        out("   ناحیه‌ای که نام در آن بود بازنویسی شده باشد، نبودنش دلیل قطعی")
        out("   بر نبودن فایل روی این ولوم نیست.")
        return
    out("   " + C.w(C.GREEN, "%d مورد پیدا شد%s"
                    % (len(res["hits"]), " (به سقف نمایش رسید)"
                       if res["truncated"] else "")))
    for h in res["hits"][:20]:
        out("      LBA %-12d offset 0x%-12X [%s]"
            % (h["lba"], h["offset"], h["encoding"]))
        if h["context"]:
            out(C.w(C.GREY, "         %s" % h["context"][:150]))
    if len(res["hits"]) > 20:
        out("      ... %d مورد دیگر" % (len(res["hits"]) - 20))


def find_first_structure(disk, p, limit_gib=16):
    """Walk forward for the first filesystem structure inside the partition.

    A bisect would be wrong here: "contains a structure" is not monotone across
    a volume, so it can land in an ordinary metadata-free gap and report a
    boundary that does not exist. Sequential is slower and cannot lie.
    """
    s = disk.sector
    p0 = p.start * s
    limit = min((p.end + 1) * s, p0 + limit_gib * 1024 * MIB)
    pos = p0
    while pos < limit:
        n = min(8 * MIB, limit - pos)
        buf = disk.read_at(pos, n + 64)
        if not buf:
            break
        best = None
        for sig, name in FORENSIC_SIGS:
            i = buf.find(sig)
            if i >= 0 and (best is None or i < best[0]):
                best = (i, name)
        if best:
            off = pos + best[0]
            if not QUIET:
                sys.stdout.write("\r" + " " * 40 + "\r")
            return {"offset": off, "lba": off // s, "what": best[1],
                    "bad_head_bytes": off - p0}
        pos += n
        if not QUIET:
            sys.stdout.write("\r    forward scan %s ...   " % human(pos - p0))
            sys.stdout.flush()
    if not QUIET:
        sys.stdout.write("\r" + " " * 40 + "\r")
    return {"offset": None, "lba": None, "what": None,
            "scanned_bytes": limit - p0}


_CONTROL_CACHE = {}


def control_baseline(args, damaged_fs=None):
    """Map a known-healthy volume with identical settings, as a control.

    Entropy alone cannot tell "a repository full of compressed backups" from
    "a volume overwritten with foreign compressed data". Without a control on
    the same host and the same workload, a high-entropy map is not evidence of
    anything. This measures the healthy case so the comparison is real.
    """
    ctl = getattr(args, "_control", None)
    if not ctl:
        return None
    key = (ctl["path"], ctl["start"], args.triage_samples, args.triage_sample_kib)
    if key in _CONTROL_CACHE:
        return _CONTROL_CACHE[key]
    try:
        d = RawDisk(ctl["path"], writable=False)
    except DiskError:
        return None
    try:
        pp = Part(ctl["start"], ctl["sectors"], "CONTROL")
        dm = damage_map(d, pp, args.triage_samples, args.triage_sample_kib)
        res = {"path": ctl["path"], "fs": ctl.get("fs"), "start": ctl["start"],
               "counts": dm["counts"], "samples": dm["samples"],
               "rows": dm["rows"]}
    finally:
        d.close()
    _CONTROL_CACHE[key] = res
    return res


def pick_control(scans):
    """Choose a healthy volume to use as the control, preferring ReFS."""
    best = None
    for path, r in scans:
        for p in r.parts:
            if type_expects_no_fs(p) or not p.fs or not p.ev:
                continue
            if p.ev.level != "strong":
                continue
            cand = {"path": path, "start": p.start, "sectors": p.sectors,
                    "fs": p.fs["fs"]}
            if p.fs["fs"] == "ReFS":
                return cand
            best = best or cand
    return best


def triage_partition(disk, p, args):
    """Full read-only forensic work-up of one damaged partition."""
    s = disk.sector
    res = {"num": p.num, "start": p.start, "end": p.end, "sectors": p.sectors}
    out("")
    out(C.w(C.BOLD, " ── TRIAGE پارتیشن #%d  LBA %d..%d  (%s) ──"
            % (p.num, p.start, p.end, human(p.sectors * s))))

    first = disk.read_at(p.start * s, s)
    head16 = disk.read_at(p.start * s, 16 * s)
    nz = [i for i in range(16) if any(head16[i * s:(i + 1) * s])]
    ent = entropy(first)
    res["first_sector_zero"] = not any(first)
    res["first_sector_entropy"] = round(ent, 2)
    res["nonzero_of_first_16"] = nz
    out("   سکتور اول    : %s" % ("کاملاً صفر" if not any(first)
                                  else "داده دارد، entropy=%.2f bit/byte" % ent))
    out("   ۱۶ سکتور اول : غیرصفر = %s" % (nz if nz else "هیچ‌کدام"))
    if any(first) and VERBOSE:
        out(hexdump(first, p.start * s, 128))

    # --- look for a ReFS volume header copy near the end -------------------
    cp = scan_refs_header_near_end(disk, p, args.triage_tail_mib)
    res["refs_header_copy"] = None
    if cp:
        h = cp["header"]
        res["refs_header_copy"] = {
            "lba": cp["lba"], "self_consistent": cp.get("self_consistent"),
            "num_sectors": h["num_sectors"], "bps": h["bytes_per_sector"],
            "spc": h["sectors_per_cluster"],
            "version": "%d.%d" % (h["major"], h["minor"])}
        out("")
        out(C.w(C.GREEN, "   نسخه header ولوم ReFS پیدا شد در LBA %d" % cp["lba"]))
        out("      NumberOfSectors   : %d  (%s)"
            % (h["num_sectors"], human(h["num_sectors"] * s)))
        out("      BytesPerSector    : %d" % h["bytes_per_sector"])
        out("      SectorsPerCluster : %d  (cluster %s)"
            % (h["sectors_per_cluster"],
               human(h["sectors_per_cluster"] * h["bytes_per_sector"])))
        out("      ReFS version      : %d.%d" % (h["major"], h["minor"]))
        if cp.get("self_consistent"):
            out(C.w(C.GREEN, "      خودسازگار: این نسخه دقیقاً در "
                             "start+NumberOfSectors-1 نشسته، یعنی طول ولوم اثبات شد."))
        else:
            out(C.w(C.YELLOW, "      ناسازگار: موقعیتش با طول اعلامی نمی‌خواند."))

    # --- structure sweep at the tail ---------------------------------------
    tail = min(args.triage_tail_mib * MIB, p.sectors * s)
    hits, empty = find_structures(disk, (p.end + 1) * s - tail, (p.end + 1) * s,
                                  progress="tail sweep")
    res["tail_structures"] = {k: v[:5] for k, v in hits.items()}
    res["tail_empty"] = empty
    out("")
    out("   انتهای پارتیشن (آخرین %s):" % human(tail))
    if empty:
        out(C.w(C.YELLOW, "      کل این ناحیه صفر است."))
    elif not hits:
        out(C.w(C.YELLOW, "      هیچ امضای شناخته‌شده‌ای نیست."))
    for k in sorted(hits):
        out("      %-22s %d هیت، اولی در LBA %d"
            % (k, len(hits[k]), hits[k][0] // s))

    # --- damage map ---------------------------------------------------------
    dm = damage_map(disk, p, args.triage_samples, args.triage_sample_kib)
    res["damage_map"] = {"counts": dm["counts"], "samples": dm["samples"],
                         "first_refs_lba": dm["first_refs_lba"],
                         "last_foreign_lba": dm["last_foreign_lba"]}
    out("")
    out("   نقشه خرابی (%d نمونه، فاصله %s):" % (dm["samples"], human(dm["step"])))
    out("      نماد: R=ReFS  #=آنتروپی بالا  d=داده  .=صفر  -=کم‌آنتروپی  "
        "F=فایل‌سیستم دیگر")
    _print_map_rows(dm["rows"], 64)
    total_n = max(1, dm["samples"])
    for k in sorted(dm["counts"], key=lambda x: -dm["counts"][x]):
        out("      %-14s %4d نمونه (%.1f%%) ≈ %s"
            % (k, dm["counts"][k], 100.0 * dm["counts"][k] / total_n,
               human(dm["counts"][k] * dm["step"])))

    # --- forward edge scan --------------------------------------------------
    # The forward scan is needed most precisely when the sampled map found no
    # structures at all: that is the case where we still do not know whether
    # metadata resumes a little further in. v1.3 skipped it exactly then.
    edge = find_first_structure(disk, p, args.triage_edge_gib)
    res["first_structure"] = edge
    out("")
    if edge["lba"] is not None:
        out("   اولین ساختار فایل‌سیستمی: %s در LBA %d  (%s بعد از شروع پارتیشن)"
            % (edge["what"], edge["lba"], human(edge["bad_head_bytes"])))
    else:
        out("   در %s اول پارتیشن هیچ ساختار فایل‌سیستمی نیست."
            % human(edge.get("scanned_bytes", 0)))

    # dense look at the head, where a targeted overwrite would land
    hm = head_map(disk, p, args.triage_head_gib, args.triage_head_samples)
    res["head_map"] = hm
    out("")
    out("   نقشه متراکم %s اول (%d نمونه، فاصله %s):"
        % (human(hm["span"]), hm["samples"], human(hm["step"])))
    _print_map_rows(hm["rows"], 64)
    for k in sorted(hm["counts"], key=lambda x: -hm["counts"][x]):
        out("      %-14s %4d نمونه (%.1f%%)"
            % (k, hm["counts"][k], 100.0 * hm["counts"][k] / max(1, hm["samples"])))

    ctl = control_baseline(args)
    res["control"] = None
    if ctl:
        cn = max(1, ctl["samples"])
        ctl_high = ctl["counts"].get("high-entropy", 0) / float(cn)
        ctl_fs = (ctl["counts"].get("refs", 0) + ctl["counts"].get("other-fs", 0)) / float(cn)
        res["control"] = {"path": ctl["path"], "fs": ctl["fs"],
                          "high_entropy": round(ctl_high, 3),
                          "fs_samples": round(ctl_fs, 3)}
        out("")
        out("   کنترل — همان اندازه‌گیری روی یک ولوم سالم (%s، %s):"
            % (os.path.basename(str(ctl["path"])) or str(ctl["path"]), ctl["fs"]))
        out("      آنتروپی بالا %.0f%%   نمونه‌های حاوی ساختار %.0f%%"
            % (ctl_high * 100, ctl_fs * 100))
        if ctl_high > 0.5:
            out(C.w(C.YELLOW, "      یعنی «آنتروپی بالا» روی این workload "
                              "تفکیک‌کننده نیست و به‌تنهایی نشانه خرابی نیست."))
    res["verdict"] = triage_verdict(disk, p, res, dm, cp, edge, res.get("control"))
    out("")
    out(C.w(C.BOLD, "   نتیجه‌گیری"))
    for ln in res["verdict"]["lines"]:
        out("      " + ln)
    out("   " + C.w(C.BOLD, "وضعیت: ") +
        C.w(res["verdict"]["color"], res["verdict"]["label"]))
    for ln in res["verdict"]["next_steps"]:
        out("      → " + ln)
    return res


def triage_verdict(disk, p, res, dm, cp, edge, control=None):
    """Turn the measurements into one conclusion and a next step.

    Two things this deliberately refuses to do:

    * Treat a high-entropy body as evidence of damage. A backup repository is
      full of compressed, often encrypted files; sampling it gives ~100%
      high entropy whether or not anything is wrong. v1.3 called that
      "widespread overwrite" and that was a false positive. Without a control
      measurement on a healthy volume of the same workload, entropy says
      nothing at all.
    * Treat "no metadata in the samples" as "no metadata". 320 samples of
      64 KiB across 1.5 TiB cover 0.001% of the volume; filesystem metadata is
      a small fraction of a full volume, so missing it is the expected outcome.

    What does carry information: whether the volume header copy and the
    structures at the tail survived, and where the first structure appears when
    walking forward from the start.
    """
    c = dm["counts"]
    n = max(1, dm["samples"])
    frac = lambda k: c.get(k, 0) / float(n)
    lines = []
    steps = []

    head_bad = edge["bad_head_bytes"] if (edge and edge.get("lba") is not None) else None
    scanned = (edge or {}).get("scanned_bytes")
    fs_present = frac("refs") + frac("other-fs")
    foreign = frac("high-entropy")
    zeros = frac("zero") + frac("sparse")

    tail_hits = res.get("tail_structures") or {}
    structure_intact = bool(
        (cp and cp.get("self_consistent")) or
        any(k.startswith("ReFS") for k in tail_hits))

    hm = res.get("head_map") or {}
    hc = hm.get("counts") or {}
    hn = max(1, hm.get("samples", 0))
    head_foreign = hc.get("high-entropy", 0) / float(hn)
    head_fs = (hc.get("refs", 0) + hc.get("other-fs", 0)) / float(hn)

    # is the entropy of this volume distinguishable from a healthy one?
    entropy_informative = True
    if control and control.get("high_entropy", 0) > 0.5:
        entropy_informative = False

    if structure_intact:
        lines.append("ساختار ولوم در انتها سالم است"
                     + (" و نسخه header خودسازگار پیدا شد؛ یعنی شروع و طول "
                        "ولوم هر دو دقیقاً درست‌اند."
                        if (cp and cp.get("self_consistent")) else "."))
    if not entropy_informative:
        lines.append("ولوم سالمِ کنترل هم %.0f%% آنتروپی بالا دارد، پس بالا بودن "
                     "آنتروپی اینجا نشانه خرابی نیست."
                     % (control["high_entropy"] * 100))

    if res["first_sector_zero"] and structure_intact and head_fs > 0:
        lines.append("سکتور اول پاک شده ولی متادیتا در همان ابتدای ولوم حاضر است.")
        label, color = "خرابی سطحی — بوت‌سکتور", C.GREEN
        steps.append("ایمیج بگیر، سپس refsutil salvage. اگر نسخه ReFS بالای "
                     "3.9 است، refsutil باید از همان build ویندوز یا جدیدتر "
                     "اجرا شود، وگرنه با پیام گمراه‌کننده رد می‌کند.")
    elif structure_intact and head_bad is not None and head_bad > 16 * MIB:
        lines.append("ابتدای ولوم به اندازه %s هیچ ساختار فایل‌سیستمی ندارد، "
                     "ولی بعد از آن متادیتا برمی‌گردد و انتهای ولوم سالم است."
                     % human(head_bad))
        lines.append("این الگوی یک بازنویسی هدفمندِ ابتدای ولوم است: ناحیه‌ای که "
                     "بوت‌سکتور و متادیتای اولیه در آن بود از بین رفته، بدنه دست‌نخورده.")
        label, color = "ابتدای ولوم بازنویسی شده (%s)" % human(head_bad), C.YELLOW
        steps.append("ایمیج کامل بگیر، بعد refsutil salvage روی ایمیج یا کپی.")
        steps.append("اگر نسخه ReFS بالای 3.9 است، اول مطمئن شو refsutil از "
                     "همان build ویندوز یا جدیدتر است.")
        steps.append("منشأ بازنویسی را پیدا کن: چه چیزی به ابتدای این ولوم نوشته.")
    elif structure_intact and head_bad is None:
        lines.append("در %s اول ولوم هیچ ساختاری پیدا نشد، ولی انتهای ولوم "
                     "کاملاً سالم است." % human(scanned or 0))
        if not entropy_informative:
            lines.append("چون آنتروپی تفکیک‌کننده نیست، نمی‌شود گفت بدنه ولوم "
                         "خراب است یا صرفاً پر از داده فشرده.")
        label = "ابتدای ولوم از بین رفته — عمق نامعلوم"
        color = C.YELLOW
        steps.append("پویش را عمیق‌تر کن تا اولین متادیتا پیدا شود: "
                     "--triage-edge-gib 128")
        steps.append("ایمیج بگیر و refsutil salvage را روی آن اجرا کن؛ "
                     "salvage از روی متادیتای بازمانده کار می‌کند و کل ولوم را "
                     "می‌گردد، نه فقط نمونه‌ها.")
    elif entropy_informative and foreign > 0.5:
        lines.append("بیش از نیمی از نمونه‌ها داده بیگانه با آنتروپی بالا هستند "
                     "و ولوم کنترل چنین الگویی ندارد.")
        label, color = "بازنویسی گسترده", C.RED
        steps.append("به ترتیب و اندازه extentهای VMDK برگرد.")
        steps.append("قبل از هر کاری ایمیج کامل بگیر.")
    elif zeros > 0.9 and not structure_intact:
        lines.append("تقریباً کل پارتیشن صفر است و هیچ ساختار سالمی در انتها نیست.")
        label, color = "ولوم عملاً خالی است", C.RED
        steps.append("سراغ فایل VMDK و بکاپ اصلی برو.")
    elif structure_intact:
        lines.append("ساختار سالم است و شاهدی بر خرابی بدنه پیدا نشد.")
        label, color = "ساختار سالم", C.GREEN
        steps.append("اگر ویندوز mount نمی‌کند، refsutil salvage. اگر نسخه "
                     "ReFS بالای 3.9 است، اول با winver مطمئن شو Windows "
                     "همان یا جدیدتر است، وگرنه refsutil با پیام گمراه‌کننده "
                     "'no recognized file system' رد می‌کند.")
    else:
        lines.append("الگوی روشنی به دست نیامد.")
        label, color = "نامشخص", C.YELLOW
        steps.append("با --triage-samples 2000 --triage-edge-gib 64 دوباره اجرا کن.")

    if cp and not cp.get("self_consistent"):
        lines.append("توجه: نسخه header پیداشده با موقعیت خودش نمی‌خواند؛ ممکن "
                     "است بازمانده یک ولوم قبلی باشد.")
    lines.append("نمونه‌های کل ولوم: ساختار=%.0f%% آنتروپی‌بالا=%.0f%% صفر=%.0f%%"
                 % (fs_present * 100, foreign * 100, zeros * 100))
    if hm:
        lines.append("نمونه‌های %s اول: ساختار=%.0f%% آنتروپی‌بالا=%.0f%%"
                     % (human(hm.get("span", 0)), head_fs * 100, head_foreign * 100))
    return {"label": label, "color": color, "lines": lines,
            "next_steps": steps, "entropy_informative": entropy_informative}


def run_triage(disk, r, args):
    """Triage every partition that is not provably healthy."""
    out("")
    out(C.w(C.BOLD, "=" * 78))
    out(C.w(C.BOLD, " TRIAGE — تشخیص عمق خرابی (فقط خواندن)"))
    out(C.w(C.BOLD, "=" * 78))
    targets = []
    for p in r.all_parts:
        if type_expects_no_fs(p):
            continue
        if p.ev and p.ev.level == "strong" and p.fs and not args.triage_all:
            continue
        targets.append(p)
    if not targets:
        ok("هیچ پارتیشن مشکوکی نیست. برای بررسی همه: --triage-all")
        return []
    results = []
    for p in targets:
        results.append(triage_partition(disk, p, args))
    return results

# =============================================================================
# SECTION 10 — Report
# =============================================================================

LEVEL_COLOR = {"strong": C.GREEN, "medium": C.YELLOW, "weak": C.GREY,
               "blocked": C.RED, "?": C.GREY}


def print_report(r):
    d = r.disk
    line = "=" * 78
    out("")
    out(C.w(C.BOLD, line))
    out(C.w(C.BOLD, " DiskDoctor %s — %s" % (VERSION, d.path)))
    out(C.w(C.BOLD, line))
    out("  size            : %s  (%d bytes)" % (human(d.size), d.size))
    out("  sector size     : %d" % d.sector)
    out("  total sectors   : %d  (last LBA %d)" % (d.sectors, d.sectors - 1))
    if r.container:
        out(C.w(C.YELLOW, "  container       : %s" % r.container))
    out("  %-15s : %s" % (T("scheme"), C.w(C.BOLD, r.scheme)))
    out("  scan time       : %.2fs%s" % (r.elapsed, "  (deep)" if r.deep_done else ""))
    out("")

    m = r.mbr
    if m:
        out(C.w(C.BOLD, " MBR (LBA 0)"))
        out("   0x55AA signature : %s" % _yn(m["signature_ok"]))
        out("   disk signature   : 0x%s" % (m["disk_sig"] or "?"))
        out("   boot code        : %s" % ("present" if m["bootcode_nonzero"] else "empty"))
        out("   protective (0xEE): %s" % ("yes" if m["protective"] else "no"))
        shown = False
        for e in m["entries"]:
            if e.empty:
                continue
            shown = True
            out("   slot %d  type=0x%02X %-24s start=%-12d sectors=%-12d (%s)" %
                (e.slot, e.type, e.type_name()[:24], e.start, e.sectors,
                 human(e.sectors * d.sector)))
        for e in m["extended_chain"]:
            out("   %-8s type=0x%02X %-24s start=%-12d sectors=%-12d (%s)" %
                (e.src, e.type, e.type_name()[:24], e.start, e.sectors,
                 human(e.sectors * d.sector)))
        if not shown:
            out("   (no non-empty primary entries)")
        out("")

    for g, label in ((r.gpt_p, "GPT primary  (LBA 1)"),
                     (r.gpt_b, "GPT backup   (last LBA)")):
        if not g:
            continue
        out(C.w(C.BOLD, " %s" % label))
        if not g["present"]:
            out("   %s" % C.w(C.RED, "missing / no EFI PART signature"))
            for e in g["errors"]:
                out("   - %s" % e)
            out("")
            continue
        h = g["header"]
        out("   header CRC       : %s" % _yn(g["header_crc_ok"]))
        out("   entries CRC      : %s" % _yn(g["entries_crc_ok"]))
        out("   revision / hdr sz: %s / %d" % (h["revision"], h["header_size"]))
        out("   disk GUID        : %s" % h["disk_guid"])
        out("   entry array      : %d x %d bytes @ LBA %d" %
            (h["entry_count"], h["entry_size"], h["entry_lba"]))
        out("   usable LBA       : %d .. %d" % (h["first_usable"], h["last_usable"]))
        out("   backup LBA       : %d %s" % (
            h["backup_lba"],
            "" if not g.get("geometry_mismatch") else C.w(C.YELLOW, "(mismatch!)")))
        out("   partitions       : %d" % len(g["entries"]))
        for e in g["errors"]:
            out("   %s" % C.w(C.YELLOW, "- " + e))
        out("")

    out(C.w(C.BOLD, " %s" % T("parts_found")))
    if not r.parts:
        out("   " + C.w(C.YELLOW, T("no_parts")))
    else:
        _print_part_table(r.parts, d.sector)
    out("")

    if r.carved:
        out(C.w(C.BOLD, " Carved by signature (not in any partition table)"))
        _print_part_table(r.carved, d.sector)
        out("")

    if EXPLAIN:
        print_evidence(r)

    if r.blockers:
        out(C.w(C.BOLD + C.RED, " %s" % T("blockers")))
        for k, why in r.blockers:
            out("   " + C.w(C.RED, "[%s] " % k) + why)
        out("")

    if r.warnings:
        out(C.w(C.BOLD + C.YELLOW, " %s" % T("warn_header")))
        for w in r.warnings:
            out("   " + C.w(C.YELLOW, "! ") + w)
        out("")


def _print_part_table(parts, sector):
    out(C.w(C.DIM, "  #   src        start LBA        end LBA      sectors      "
                   "size  fs           level   conf"))
    for p in parts:
        ev = p.ev
        col = LEVEL_COLOR.get(p.level, C.GREY)
        conf = ("%3.0f%%" % (ev.confidence * 100)) if ev else "  -"
        out(C.w(col, "  %-3d %-10s %12d %12d %12d %9s  %-12s %-7s %s" % (
            p.num, p.source[:10], p.start, p.end, p.sectors,
            human(p.sectors * sector), p.fs_name()[:12], p.level, conf)))
        out(C.w(C.GREY, "        type   : %s" % (p.type_name or p.type_id or "-")))
        if p.name:
            out(C.w(C.GREY, "        label  : %s" % p.name))
        out(C.w(C.GREY, "        extent : %s" %
                ((ev.extent_source or "NOT PROVEN") if ev else "-")))
        if ev and ev.blockers:
            for k, why in ev.blockers:
                out(C.w(C.RED, "        BLOCKER %s: %s" % (k, why)))


def print_evidence(r):
    out(C.w(C.BOLD, " %s" % T("evidence")))
    for p in r.all_parts:
        ev = p.ev
        if not ev:
            continue
        out(C.w(C.BOLD, "   #%d  %s  LBA %d..%d  (%s)  score %d/%d = %.0f%%  [%s]" %
                (p.num, p.fs_name(), p.start, p.end,
                 human(p.sectors * r.disk.sector), ev.score, ev.max_score,
                 ev.confidence * 100, ev.level)))
        for k in sorted(ev.signals.keys()):
            s = ev.signals[k]
            if s["value"] is None:
                mark, col = "n/a ", C.GREY
            elif s["value"]:
                mark, col = "PASS", C.GREEN
            else:
                mark, col = "FAIL", C.RED
            out("      " + C.w(col, "%-4s" % mark) +
                " %-18s %s" % (k, s["why"][:90]))
        out("      %-4s %-18s %s" % ("", "extent",
                                     ev.extent_source or "NOT PROVEN"))
        for k, why in ev.blockers:
            out("      " + C.w(C.RED, "BLK  %-18s %s" % (k, why)))
        out("")


def _yn(v):
    if v is None:
        return "?"
    return C.w(C.GREEN, "OK") if v else C.w(C.RED, "BAD")


# =============================================================================
# SECTION 11 — Patch transaction + journal
# =============================================================================
# Recovery rule: the journal must exist on disk, fsynced, BEFORE the first byte
# is written. A crash mid-transaction must leave a journal that says exactly
# which patches were already applied.
# =============================================================================

class Patch(object):
    def __init__(self, offset, new, label, old=None):
        self.offset = int(offset)
        self.new = bytes(new)
        self.old = old
        self.label = label
        self.status = "pending"

    def load_old(self, disk):
        if self.old is None:
            self.old = disk.read_at(self.offset, len(self.new))
        return self.old

    def changed(self):
        return self.old != self.new

    def to_dict(self, index):
        return {"i": index, "offset": self.offset, "label": self.label,
                "len": len(self.new), "status": self.status,
                "old_b64": base64.b64encode(self.old or b"").decode(),
                "new_b64": base64.b64encode(self.new).decode(),
                "sha_old": hashlib.sha256(self.old or b"").hexdigest(),
                "sha_new": hashlib.sha256(self.new).hexdigest()}


def _atomic_write_json(path, data):
    # Reports are immutable artifacts too; output collisions never truncate data.
    core.durable_json(path, data)


class PatchTransaction(core.Transaction):
    """Fail-closed compatibility name; full v2 preconditions are mandatory."""
    pass


def load_journal(path):
    raise DiskError("Mutable v1 journals are read-only historical artifacts; use a v2 transaction ID")


def inspect_journal(path):
    # Historical inspection is permitted; it cannot authorize a mutation.
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    out(json.dumps(doc, ensure_ascii=False, indent=2))
    return doc


def undo_journal(path, force=False):
    raise DiskError("Legacy journal rollback is disabled; use --undo TRANSACTION_UUID")


def check_journals(backup_dir):
    if not os.path.isdir(backup_dir):
        return EXIT_OK
    interrupted = False
    for name in sorted(os.listdir(backup_dir)):
        directory = os.path.join(backup_dir, name)
        if not os.path.isdir(directory):
            continue
        try:
            doc = core.inspect_transaction(backup_dir, name)
            out(name + " " + doc["state"])
            interrupted = interrupted or doc["interrupted"]
        except (core.SafetyError, OSError, ValueError) as e:
            err(name + ": " + str(e))
            interrupted = True
    return EXIT_ERR if interrupted else EXIT_OK


def dump_structures(disk, backup_dir, tag="pre"):
    """Save the first and last 34 sectors before any structural change."""
    os.makedirs(backup_dir, exist_ok=True)
    ts = str(uuid.uuid4())
    base = os.path.join(backup_dir, "struct_%s_%s" % (tag, ts))
    head = disk.read_at(0, 34 * disk.sector)
    tail_off = max(0, disk.size - 34 * disk.sector)
    tail = disk.read_at(tail_off, 34 * disk.sector)
    for suffix, data in (("_head.bin", head), ("_tail.bin", tail)):
        core.durable_create(base + suffix, data)
    _atomic_write_json(base + "_meta.json", {
        "head_offset": 0, "tail_offset": tail_off, "sector": disk.sector,
        "target": disk.path,
        "head_sha256": hashlib.sha256(head).hexdigest(),
        "tail_sha256": hashlib.sha256(tail).hexdigest()})
    return base


def preview_patches(disk, patches):
    out("")
    out(C.w(C.BOLD, " %s" % T("dryrun")))
    total = 0
    for p in patches:
        p.load_old(disk)
        state = "CHANGE" if p.changed() else "no-op"
        total += len(p.new) if p.changed() else 0
        out("   %-42s @ 0x%012X  %6d bytes  [%s]" %
            (p.label[:42], p.offset, len(p.new), state))
        if VERBOSE and p.changed():
            out(hexdiff(p.old, p.new, p.offset))
    out("   total bytes to write: %d" % total)
    out("")
    return total


# =============================================================================
# SECTION 12 — Repair actions
# =============================================================================
# Every builder returns a RepairAction carrying its gate class, or raises
# Blocked with the exact reasons. A builder never "falls back" to a weaker
# source when the strong one is missing.
# =============================================================================

FS_TO_MBR_TYPE = {
    "NTFS": 0x07, "ReFS": 0x07, "exFAT": 0x07, "BitLocker": 0x07,
    "FAT32": 0x0C, "FAT16": 0x06, "FAT12": 0x01,
    "ext2/3": 0x83, "ext4": 0x83, "XFS": 0x83, "Btrfs": 0x83,
    "Linux swap": 0x82, "LVM2 PV": 0x8E, "HFS+": 0xAF, "VMFS": 0xFB,
}
FS_TO_GPT_GUID = {
    "NTFS": GUID_MSDATA, "ReFS": GUID_MSDATA, "exFAT": GUID_MSDATA,
    "BitLocker": GUID_MSDATA, "FAT32": GUID_MSDATA, "FAT16": GUID_MSDATA,
    "FAT12": GUID_MSDATA, "ext2/3": GUID_LINUX, "ext4": GUID_LINUX,
    "XFS": GUID_LINUX, "Btrfs": GUID_LINUX,
    "Linux swap": "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F",
    "LVM2 PV": "E6D6D379-F507-44C2-A23C-238F2A3DF928",
    "HFS+": "48465300-0000-11AA-AA11-00306543ECAC",
    "VMFS": "AA31E02A-400F-11DB-9590-000C2911D1B8",
}


class Blocked(Exception):
    def __init__(self, action, reasons):
        self.action = action
        self.reasons = reasons if isinstance(reasons, (list, tuple)) else [reasons]
        Exception.__init__(self, "; ".join(self.reasons))


class RepairAction(object):
    def __init__(self, key, title, patches, gate, note="", post=(), notes=()):
        self.key = key
        self.write_class = safety.classify(key)
        self.source_fingerprint = None
        self.provenance = None
        self.structural_oracle = None
        self.semantic_oracle = None
        self.title = title
        self.patches = patches
        self.gate = gate
        self.note = note
        self.post = list(post)
        self.notes = list(notes)


# --- GPT: byte-for-byte restores ---------------------------------------------

def act_gpt_restore_primary(disk, r, args):
    safety.redundant_conflicts(sys.modules[__name__], r, "gpt-restore-primary")
    src = r.gpt_b
    if not (src and src["present"]):
        raise Blocked("gpt-restore-primary", "هیچ GPT پشتیبانی در انتهای دیسک نیست")
    if not src["valid"]:
        raise Blocked("gpt-restore-primary",
                      ["GPT پشتیبان خودش معتبر نیست: " + "; ".join(src["errors"]),
                       "کپی کردن یک ساختار خراب روی ساختار خراب دیگر ممنوع است"])
    h = src["header"]
    es = gpt_entries_sectors(h, disk.sector)
    entry_lba = 2
    if h["first_usable"] and entry_lba + es > h["first_usable"]:
        raise Blocked("gpt-restore-primary",
                      "آرایه ورودی‌ها در LBA 2 با FirstUsableLBA=%d جا نمی‌شود"
                      % h["first_usable"])
    hdr = gpt_transplant_header(src["header_sector"], disk.sector,
                                my_lba=1, alt_lba=h["current_lba"],
                                entry_lba=entry_lba)
    patches = [
        Patch(entry_lba * disk.sector, src["entry_bytes"],
              "GPT entry array verbatim from backup -> LBA %d" % entry_lba),
        Patch(1 * disk.sector, hdr,
              "GPT primary header (transplanted, only MyLBA/AltLBA/EntryLBA+CRC changed)"),
    ]
    return RepairAction(
        "gpt-restore-primary",
        "بازنویسی GPT اصلی از روی پشتیبانِ معتبر (%d پارتیشن، byte-for-byte)"
        % len(src["entries"]),
        patches, GATE_SAFE,
        note="آرایه ورودی‌ها عیناً کپی می‌شود. از هدر فقط MyLBA، AlternateLBA، "
             "PartitionEntryLBA و CRC تغییر می‌کند؛ entry_size، revision، "
             "reserved و Disk GUID دست‌نخورده می‌ماند.",
        post=["rescan"])


def act_gpt_restore_backup(disk, r, args):
    safety.redundant_conflicts(sys.modules[__name__], r, "gpt-restore-backup")
    src = r.gpt_p
    if not (src and src["present"]):
        raise Blocked("gpt-restore-backup", "GPT اصلی وجود ندارد")
    if not src["valid"]:
        raise Blocked("gpt-restore-backup",
                      ["GPT اصلی معتبر نیست: " + "; ".join(src["errors"])])
    h = src["header"]
    es = gpt_entries_sectors(h, disk.sector)
    bak_hdr_lba = h["backup_lba"]
    if not (0 < bak_hdr_lba < disk.sectors):
        raise Blocked("gpt-restore-backup",
                      "AlternateLBA=%d خارج از دیسک است (اول gpt-fix-geometry)"
                      % bak_hdr_lba)
    bak_ent_lba = bak_hdr_lba - es
    if bak_ent_lba <= h["last_usable"]:
        raise Blocked("gpt-restore-backup",
                      "محل آرایه پشتیبان (%d) با LastUsableLBA=%d تداخل دارد"
                      % (bak_ent_lba, h["last_usable"]))
    hdr = gpt_transplant_header(src["header_sector"], disk.sector,
                                my_lba=bak_hdr_lba, alt_lba=1, entry_lba=bak_ent_lba)
    patches = [
        Patch(bak_ent_lba * disk.sector, src["entry_bytes"],
              "GPT entry array verbatim from primary -> LBA %d" % bak_ent_lba),
        Patch(bak_hdr_lba * disk.sector, hdr,
              "GPT backup header (transplanted) -> LBA %d" % bak_hdr_lba),
    ]
    return RepairAction(
        "gpt-restore-backup",
        "بازسازی GPT پشتیبان از روی نسخه اصلی معتبر (byte-for-byte)",
        patches, GATE_SAFE,
        note="فقط انتهای دیسک نوشته می‌شود.", post=["rescan"])


def act_gpt_fix_crc(disk, r, args):
    """Correct ONLY the two CRC fields, on the existing on-disk header bytes."""
    safety.proven_crc(sys.modules[__name__], r)
    targets = []
    for g, side, lba in ((r.gpt_p, "primary", 1),
                         (r.gpt_b, "backup", disk.sectors - 1)):
        if not (g and g["present"]):
            continue
        if g["header_crc_ok"] and g["entries_crc_ok"]:
            continue
        targets.append((g, side, g.get("header_lba", lba)))
    if not targets:
        raise Blocked("gpt-fix-crc", "هیچ هدر GPTی با CRC خراب پیدا نشد")
    patches = []
    notes = []
    for g, side, lba in targets:
        plausible, why = gpt_entries_plausible(g, disk.sectors)
        if not plausible:
            raise Blocked("gpt-fix-crc",
                          ["آرایه ورودی‌های %s خودش منطقی نیست، پس اصلاح CRC "
                           "فقط خرابی را تایید می‌کند: %s" % (side, "; ".join(why)),
                           "به‌جایش gpt-restore-primary یا gpt-restore-backup را "
                           "از سمت سالم اجرا کن"])
        new_hdr = gpt_recrc_header(g["header_sector"], disk.sector, g["entry_bytes"])
        patches.append(Patch(lba * disk.sector, new_hdr,
                             "GPT %s header: CRC fields only (offsets 16 and 88)" % side))
        notes.append("%s: header_crc_ok=%s entries_crc_ok=%s"
                     % (side, g["header_crc_ok"], g["entries_crc_ok"]))
    return RepairAction(
        "gpt-fix-crc", "اصلاح فقط فیلدهای CRC هدر GPT (%d سمت)" % len(patches),
        patches, GATE_SAFE,
        note="هیچ فیلد دیگری از هدر و هیچ بایتی از آرایه ورودی‌ها تغییر نمی‌کند.",
        post=["rescan"], notes=notes)


def act_gpt_fix_geometry(disk, r, args):
    """Re-anchor a GPT whose stored geometry disagrees with the real disk."""
    safety.geometry_provenance(sys.modules[__name__], disk, r, args)
    src = r.gpt_p if (r.gpt_p and r.gpt_p["present"] and r.gpt_p["entries"]) else r.gpt_b
    if not (src and src["present"] and src["entries"]):
        raise Blocked("gpt-fix-geometry", "هیچ هدر GPT قابل استفاده‌ای نیست")
    h = src["header"]
    es = gpt_entries_sectors(h, disk.sector)
    new_alt = disk.sectors - 1
    new_last_usable = disk.sectors - 2 - es
    bak_ent_lba = new_alt - es
    bad = []
    for e in src["entries"]:
        if e.last > new_last_usable:
            bad.append("پارتیشن %d تا LBA %d ادامه دارد ولی LastUsable جدید %d است"
                       % (e.index, e.last, new_last_usable))
    if bad:
        raise Blocked("gpt-fix-geometry",
                      bad + ["دیسک برای همین جدول کوچک است. اندازه extent در "
                             "VMDK را درست کن، ابزار نمی‌تواند این را حل کند."])
    prim = gpt_transplant_header(src["header_sector"], disk.sector, my_lba=1,
                                 alt_lba=new_alt, entry_lba=2,
                                 last_usable=new_last_usable)
    bak = gpt_transplant_header(src["header_sector"], disk.sector, my_lba=new_alt,
                                alt_lba=1, entry_lba=bak_ent_lba,
                                last_usable=new_last_usable)
    patches = [
        Patch(2 * disk.sector, src["entry_bytes"], "GPT primary entry array (verbatim)"),
        Patch(1 * disk.sector, prim, "GPT primary header re-anchored to the real disk size"),
        Patch(bak_ent_lba * disk.sector, src["entry_bytes"],
              "GPT backup entry array (verbatim) -> LBA %d" % bak_ent_lba),
        Patch(new_alt * disk.sector, bak, "GPT backup header -> LBA %d" % new_alt),
    ]
    return RepairAction(
        "gpt-fix-geometry",
        "اصلاح هندسه GPT: AlternateLBA=%d، LastUsableLBA=%d" % (new_alt, new_last_usable),
        patches, GATE_INFERRED,
        note="ورودی‌های پارتیشن عیناً حفظ می‌شوند؛ فقط مختصات انتهای دیسک "
             "به‌روز می‌شود. اگر اندازه واقعی VMDK غلط باشد این اقدام غلط را "
             "تثبیت می‌کند — اول از درستی اندازه دیسک مطمئن شو.",
        post=["rescan"])


def act_mbr_protective(disk, r, args):
    if not ((r.gpt_p and r.gpt_p["valid"]) or (r.gpt_b and r.gpt_b["valid"])):
        raise Blocked("mbr-write-protective",
                      "هیچ GPT معتبری نیست؛ نوشتن Protective MBR بی‌معنا است")
    old = disk.read_lba(0, 1)
    boot = old if (r.mbr and r.mbr["bootcode_nonzero"]) else b""
    sec = build_protective_mbr(disk.sectors, boot)
    sec = bytearray(sec)
    sec[0x1B8:0x1BE] = old[0x1B8:0x1BE]
    sec = bytes(sec)
    return RepairAction(
        "mbr-write-protective", "نوشتن Protective MBR روی سکتور 0",
        [Patch(0, sec, "protective MBR (LBA 0)")], GATE_SAFE,
        note="فقط سکتور 0. کد بوت موجود حفظ می‌شود.", post=["rescan"])


# --- inferred rebuilds --------------------------------------------------------

def strong_candidates(r):
    """Only candidates whose evidence is strong AND whose length is proven.

    There is deliberately no fallback: if nothing is strong, the caller gets an
    empty list and must block, not lower its standards.
    """
    res = []
    for p in sorted(r.all_parts, key=lambda x: x.start):
        if not p.ev or p.ev.level != "strong":
            continue
        res.append(p)
    return res


def _rebuild_preconditions(disk, r, key):
    reasons = []
    for k, why in r.blockers:
        reasons.append("[%s] %s" % (k, why))
    strong = strong_candidates(r)
    weak = [p for p in r.all_parts if p not in strong]
    if not strong:
        reasons.append("هیچ کاندیدی به سطح strong نرسید؛ بدون طول اثبات‌شده "
                       "هیچ جدولی ساخته نمی‌شود")
    for p in weak:
        ev = p.ev
        if not ev:
            continue
        detail = ", ".join(ev.failed()[:4]) or "-"
        reasons.append("پارتیشن #%d (%s @LBA %d) در سطح %s است — سیگنال‌های "
                       "ناموفق: %s%s"
                       % (p.num, p.fs_name(), p.start, ev.level, detail,
                          "؛ blocker: " + ev.blockers[0][1] if ev.blockers else ""))
    if reasons:
        raise Blocked(key, reasons)
    return strong


def act_mbr_rebuild(disk, r, args):
    parts = _rebuild_preconditions(disk, r, "mbr-rebuild")
    if len(parts) > 4:
        raise Blocked("mbr-rebuild",
                      "MBR فقط 4 پارتیشن اصلی دارد و %d کاندید قوی هست — "
                      "gpt-rebuild را استفاده کن" % len(parts))
    if disk.size > 2 * TIB:
        raise Blocked("mbr-rebuild", "دیسک بزرگ‌تر از 2TiB با MBR توصیف نمی‌شود")
    unknown = [p for p in parts if p.fs_name() not in FS_TO_MBR_TYPE]
    if unknown:
        raise Blocked("mbr-rebuild",
                      ["فایل‌سیستم پارتیشن #%d (%s) شناخته‌شده نیست و این ابزار "
                       "نوع پارتیشن را حدس نمی‌زند" % (p.num, p.fs_name())
                       for p in unknown])
    old = disk.read_lba(0, 1)
    sec = bytearray(512)
    if len(old) == 512 and any(old[0:0x1B8]):
        sec[0:0x1BE] = old[0:0x1BE]
    elif len(old) == 512:
        sec[0x1B8:0x1BC] = old[0x1B8:0x1BC]
    for i, p in enumerate(parts):
        sec[0x1BE + i * 16:0x1BE + (i + 1) * 16] = build_mbr_entry(
            FS_TO_MBR_TYPE[p.fs_name()], p.start, min(p.sectors, 0xFFFFFFFF),
            bootable=False)
    sec[510:512] = b"\x55\xAA"
    desc = ", ".join("%s@%d(%s)" % (p.fs_name(), p.start,
                                    p.ev.extent_source.split()[0]) for p in parts)
    return RepairAction(
        "mbr-rebuild", "ساخت جدول MBR از %d کاندید strong: %s" % (len(parts), desc),
        [Patch(0, bytes(sec), "MBR partition table (LBA 0)")], GATE_INFERRED,
        note="فقط سکتور 0. کد بوت و امضای دیسک حفظ می‌شود.",
        post=["rescan"],
        notes=["#%d %s LBA %d..%d — extent proof: %s"
               % (p.num, p.fs_name(), p.start, p.end, p.ev.extent_source)
               for p in parts])


def act_gpt_rebuild(disk, r, args):
    # Preserve discovery/evidence; refuse to synthesize historical GUIDs,
    # attributes, names or EFI roles. Operator identity import is not supported.
    _rebuild_preconditions(disk, r, "gpt-rebuild")
    raise Blocked("gpt-rebuild", "BLOCKED_INSUFFICIENT_EVIDENCE: exact historical GPT identity is UNKNOWN")


# --- VBR restore --------------------------------------------------------------
# The mirror is only accepted when it validates against the partition extent on
# its own terms. Signature alone is never enough: an NTFS boot sector sitting in
# the last sector of a WRONG partition size would otherwise be copied over a
# healthy volume start.

def find_validated_mirror(disk, p):
    """Locate and validate a backup boot sector for a partition.

    Returns dict(src_lba, count, fs, checks[], ok, reasons[]) or None if no
    mirror-capable signature exists at all.
    """
    res = {"src_lba": None, "count": 0, "fs": None, "checks": [], "reasons": [],
           "ok": False}

    # ---- NTFS: mirror is the last sector of the volume --------------------
    if p.sectors > 1 and p.end < disk.sectors:
        sec = disk.read_lba(p.end, 1)
        if sec[3:11] == b"NTFS    ":
            f = ntfs_fields(sec)
            res.update(src_lba=p.end, count=1, fs="NTFS")
            sane = ntfs_fields_sane(f)
            res["checks"].append(("mirror BPB self-consistent", sane, _ntfs_why(f)))
            span_ok = (f["total_sectors"] == p.sectors - 1)
            res["checks"].append((
                "mirror length matches the partition extent", span_ok,
                "mirror says %d sectors, partition span implies %d"
                % (f["total_sectors"], p.sectors - 1)))
            hid_ok = (f["hidden_sectors"] in (p.start, 0))
            res["checks"].append(("BPB_HiddSec agrees with the start LBA", hid_ok,
                                  "HiddSec=%d start=%d" % (f["hidden_sectors"], p.start)))
            res["ok"] = bool(sane and span_ok)
            if not span_ok:
                res["reasons"].append(
                    "آینه NTFS طول %d سکتور را اعلام می‌کند ولی پارتیشن %d سکتور "
                    "است. یا مرز پارتیشن غلط است یا این آینه متعلق به ولوم دیگری "
                    "است. کپی کردنش ولوم را خراب‌تر می‌کند."
                    % (f["total_sectors"], p.sectors - 1))
            if not sane:
                res["reasons"].append("فیلدهای BPB آینه با هم سازگار نیستند")
            return res

    # ---- exFAT: sectors 12..23 mirror sectors 0..11 -----------------------
    sec = disk.read_lba(p.start + 12, 1)
    if sec[3:11] == b"EXFAT   ":
        f = exfat_fields(sec)
        res.update(src_lba=p.start + 12, count=12, fs="exFAT")
        off_ok = (f["partition_offset"] == p.start)
        res["checks"].append(("PartitionOffset matches the start LBA", off_ok,
                              "%d vs %d" % (f["partition_offset"], p.start)))
        len_ok = (0 < f["volume_length"] <= p.sectors)
        res["checks"].append(("declared volume length fits the partition", len_ok,
                              "%d vs %d" % (f["volume_length"], p.sectors)))
        cs_ok, cs_why = exfat_checksum_ok(disk, p.start + 12, f["bps"] or disk.sector)
        res["checks"].append(("mirror VBR checksum valid", cs_ok, cs_why))
        res["ok"] = bool(off_ok and len_ok and cs_ok)
        if not off_ok:
            res["reasons"].append("PartitionOffset آینه با LBA شروع نمی‌خواند")
        if not cs_ok:
            res["reasons"].append("چک‌سام VBR آینه معتبر نیست: %s" % cs_why)
        return res

    # ---- FAT32: backup boot sector, normally at sector 6 ------------------
    for bk in (6, 12, 1):
        sec = disk.read_lba(p.start + bk, 1)
        if sec[0x52:0x5A] != b"FAT32   " and not _looks_like_fat32(sec):
            continue
        f = fat_fields(sec, 32)
        res.update(src_lba=p.start + bk, count=3, fs="FAT32")
        sane = fat_fields_sane(f) and _fat_geometry_ok(f)
        res["checks"].append(("mirror BPB self-consistent", sane, _fat_why(f, True)))
        bk_ok = (f["bk_boot_sec"] == bk)
        res["checks"].append(("BPB_BkBootSec points at this very sector", bk_ok,
                              "BkBootSec=%d, found at +%d" % (f["bk_boot_sec"], bk)))
        hid_ok = (f["hidden_sectors"] in (p.start, 0))
        res["checks"].append(("BPB_HiddSec agrees with the start LBA", hid_ok,
                              "HiddSec=%d start=%d" % (f["hidden_sectors"], p.start)))
        len_ok = (0 < f["total_sectors"] <= p.sectors)
        res["checks"].append(("declared length fits the partition", len_ok,
                              "%d vs %d" % (f["total_sectors"], p.sectors)))
        res["ok"] = bool(sane and bk_ok and len_ok)
        if not bk_ok:
            res["reasons"].append("BPB_BkBootSec آینه به خودش اشاره نمی‌کند "
                                  "(%d به‌جای %d) — این نسخه پشتیبان معتبر نیست"
                                  % (f["bk_boot_sec"], bk))
        if not len_ok:
            res["reasons"].append("طول اعلام‌شده آینه از پارتیشن بزرگ‌تر است")
        return res

    return None


def act_vbr_restore(disk, r, args, reverse=False):
    key = "vbr-restore-reverse" if reverse else "vbr-restore"
    if args.part is None:
        raise Blocked(key, "این اقدام به شماره پارتیشن نیاز دارد: --part N")
    p = _find_part(r, args.part)
    if p is None:
        raise Blocked(key, "پارتیشن #%s در نتیجه این اسکن نیست" % args.part)
    if p.fs and p.fs["fs"] == "ReFS":
        raise Blocked(key, ["ReFS آینه بوت‌سکتور ندارد. هیچ ترمیم سطح-سکتوری روی "
                            "ReFS انجام نمی‌شود.",
                            "مسیر درست: --action refsutil (refsutil salvage)"])
    if p.fs and p.fs["fs"] == "BitLocker":
        raise Blocked(key, "ولوم BitLocker است؛ بدون کلید بازیابی معنا ندارد")

    mir = find_validated_mirror(disk, p)
    if not mir:
        raise Blocked(key, "هیچ نسخه آینه‌ای پیدا نشد (نه آخرین سکتور NTFS، نه "
                           "سکتور 6 فت‌سی‌وودو، نه سکتور 12 اگزافت)")
    if not mir["ok"]:
        raise Blocked(key, mir["reasons"] or ["اعتبارسنجی آینه شکست خورد"])

    s = disk.sector
    if not reverse:
        data = disk.read_lba(mir["src_lba"], mir["count"])
        tgt = p.start
        title = ("ترمیم Boot Sector پارتیشن #%d (%s) از آینه اعتبارسنجی‌شده در LBA %d"
                 % (p.num, mir["fs"], mir["src_lba"]))
    else:
        ev = p.ev
        if not (ev and ev.signals.get("bpb_consistency", {}).get("value")):
            raise Blocked(key, "نسخه اصلی خودش سالم نیست؛ کپی کردنش روی آینه "
                               "خرابی را تکثیر می‌کند")
        data = disk.read_lba(p.start, mir["count"])
        tgt = mir["src_lba"]
        title = ("بازنویسی آینه پارتیشن #%d (%s) از روی نسخه اصلی سالم"
                 % (p.num, mir["fs"]))
    if len(data) < mir["count"] * s:
        raise Blocked(key, "خواندن ناقص منبع")
    checks = ["%s: %s (%s)" % ("PASS" if okk else "FAIL", nm, why)
              for nm, okk, why in mir["checks"]]
    return RepairAction(
        key, title,
        [Patch(tgt * s, data, "%s VBR x%d sectors -> LBA %d"
               % (mir["fs"], mir["count"], tgt))],
        GATE_SAFE,
        note="منبع یک ساختار موجود و اعتبارسنجی‌شده روی همین دیسک است. "
             "در ویندوز ممکن است --offline لازم باشد.",
        post=["chkdsk"], notes=checks)


def act_parttype_fix(disk, r, args):
    raise Blocked("parttype-fix", "BLOCKED_INSUFFICIENT_EVIDENCE: filesystem appearance does not prove partition semantic identity")


def _find_part(r, num):
    for p in r.all_parts:
        if p.num == int(num):
            return p
    return None


ACTION_BUILDERS = {
    "gpt-restore-primary": act_gpt_restore_primary,
    "gpt-restore-backup": act_gpt_restore_backup,
    "gpt-fix-crc": act_gpt_fix_crc,
    "gpt-fix-geometry": act_gpt_fix_geometry,
    "mbr-write-protective": act_mbr_protective,
    "mbr-rebuild": act_mbr_rebuild,
    "gpt-rebuild": act_gpt_rebuild,
    "vbr-restore": lambda d, r, a: act_vbr_restore(d, r, a, False),
    "vbr-restore-reverse": lambda d, r, a: act_vbr_restore(d, r, a, True),
    "parttype-fix": act_parttype_fix,
}
EXTERNAL_ACTIONS = ("chkdsk", "refsutil", "rescan")
# actions allowed to run even when a disk-level blocker is active
BLOCKER_EXEMPT = {"gpt-fix-geometry": ("geometry_mismatch", "mbr_out_of_range")}


# =============================================================================
# SECTION 13 — Planner
# =============================================================================

def suggest_plans(disk, r):
    plans = []

    def add(key, why, part=None):
        plans.append({"action": key, "why": why, "part": part})

    gp, gb = r.gpt_p, r.gpt_b
    if gp and gb:
        if not gp["valid"] and gb["valid"]:
            add("gpt-restore-primary", "GPT اصلی خراب، پشتیبان معتبر — کپی "
                                       "byte-for-byte، بدون هیچ استنتاجی.")
        if gp["valid"] and not gb["valid"]:
            add("gpt-restore-backup", "GPT پشتیبان خراب/غایب، اصلی معتبر.")
        for g, side in ((gp, "اصلی"), (gb, "پشتیبان")):
            if g["present"] and not (g["header_crc_ok"] and g["entries_crc_ok"]):
                plausible, _ = gpt_entries_plausible(g, disk.sectors)
                if plausible:
                    add("gpt-fix-crc", "CRC هدر %s غلط است ولی ورودی‌ها منطقی‌اند."
                        % side)
                break
        if gp.get("geometry_mismatch") and gp.get("entries"):
            add("gpt-fix-geometry", "اندازه واقعی دیسک با هندسه داخل GPT نمی‌خواند.")
    if (gp and gp["valid"]) and r.mbr and not r.mbr["protective"]:
        add("mbr-write-protective", "GPT معتبر است ولی Protective MBR نیست.")

    table_dead = (not r.parts) or r.scheme.startswith("RAW")
    if table_dead:
        strong = strong_candidates(r)
        if strong:
            if len(strong) <= 4 and disk.size <= 2 * TIB:
                add("mbr-rebuild", "جدول نیست و %d ولوم با طول اثبات‌شده پیدا شد."
                    % len(strong))
            add("gpt-rebuild", "بازسازی GPT از %d ولوم با طول اثبات‌شده." % len(strong))
        elif r.all_parts:
            add("__none__", "ولوم‌هایی پیدا شد ولی هیچ‌کدام طول اثبات‌شده ندارند؛ "
                            "بازسازی جدول مجاز نیست. با --explain دلیل هر کدام "
                            "را ببین.")

    for p in r.all_parts:
        if type_expects_no_fs(p):
            continue
        if p.fs and p.fs["fs"] == "ReFS":
            if p.ev and p.ev.level == "strong":
                continue          # a healthy ReFS volume needs nothing
            ver = (p.fs.get("fields") or {}).get("version")
            note = ("پارتیشن #%d از نوع ReFS (نسخه %s) است و سالم تشخیص "
                    "داده نشد." % (p.num, ver or "?"))
            add("refsutil", note, part=p.num)
            continue
        if p.fs is None or (p.fs and p.fs["conf"] < 0.5):
            mir = find_validated_mirror(disk, p)
            if mir and mir["ok"]:
                add("vbr-restore", "پارتیشن #%d بوت‌سکتور ندارد و آینه‌اش "
                                   "اعتبارسنجی شد." % p.num, part=p.num)
            elif mir:
                add("__none__", "پارتیشن #%d آینه دارد ولی اعتبارسنجی رد شد: %s"
                    % (p.num, "; ".join(mir["reasons"][:2])))
        elif p.ev and p.ev.signals.get("mirror_signature", {}).get("value") is False \
                and p.ev.signals.get("bpb_consistency", {}).get("value"):
            add("vbr-restore-reverse", "پارتیشن #%d سالم است ولی آینه‌اش خراب/غایب."
                % p.num, part=p.num)

    if r.parts and r.scheme.startswith("MBR"):
        for p in r.parts:
            if p.fs and p.source == "MBR" and p.type_id and p.ev \
                    and p.ev.level in ("strong", "medium"):
                want = FS_TO_MBR_TYPE.get(p.fs_name())
                try:
                    cur = int(p.type_id, 16)
                except Exception:
                    cur = None
                if want is not None and cur is not None and cur != want:
                    add("parttype-fix", "نوع پارتیشن #%d با فایل‌سیستم واقعی "
                                        "نمی‌خواند." % p.num)
                    break

    seen, uniq = set(), []
    for pl in plans:
        k = (pl["action"], pl["part"])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(pl)
    return uniq


GATE_LABEL = {GATE_SAFE: C.GREEN, GATE_INFERRED: C.YELLOW, GATE_BLOCKED: C.RED}


def print_plans(disk, r, plans):
    out(C.w(C.BOLD, " %s" % T("plan_header")))
    if not plans:
        out("   " + T("no_plan"))
        out("")
        return
    for i, p in enumerate(plans, 1):
        if p["action"] == "__none__":
            out("   " + C.w(C.RED, "•  ") + p["why"])
            continue
        gate = probe_gate(disk, r, p["action"], p.get("part"))
        tag = "%s%s" % (p["action"], (" --part %d" % p["part"]) if p["part"] else "")
        out("   %d) %-32s %s  %s" % (
            i, C.w(C.BOLD, tag),
            C.w(GATE_LABEL.get(gate, C.GREY), "[%s]" % gate), p["why"]))
    out("")


def probe_gate(disk, r, action, part=None):
    if action in EXTERNAL_ACTIONS:
        return GATE_BLOCKED if action == "chkdsk" else GATE_SAFE
    builder = ACTION_BUILDERS.get(action)
    if not builder:
        return GATE_BLOCKED
    try:
        act = builder(disk, r, argparse.Namespace(part=part))
        if act.write_class not in core.ELIGIBLE:
            return GATE_BLOCKED
        if any(k not in BLOCKER_EXEMPT.get(action, ()) for k, _ in r.blockers):
            return GATE_BLOCKED
        return act.gate
    except (Blocked, core.SafetyError):
        return GATE_BLOCKED


# =============================================================================
# SECTION 14 — Forensic imager
# =============================================================================
# A read error is never silently turned into zeros. Chunk read → retry →
# sector-level descent → recorded bad range. The fill pattern is recorded in
# the badmap so a later analysis can tell filler from real data.
# =============================================================================

FILL_PATTERNS = {
    "zero": b"\x00" * 512,
    "pat": (b"DISKDOCTOR-UNREADABLE-SECTOR-" * 32)[:512],
}


def _fill_block(kind, n):
    unit = FILL_PATTERNS.get(kind, FILL_PATTERNS["zero"])
    return (unit * ((n // len(unit)) + 1))[:n]


def make_image(disk, path, limit=0, chunk=8 * MIB, retries=3, fill="pat",
               resume=False, final_hash=False):
    return imaging.make_image(sys.modules[__name__], disk, path, limit, chunk,
                              retries, fill, resume, final_hash)


def _read_retry(disk, off, n, retries):
    for attempt in range(max(1, retries)):
        try:
            d = disk.read_at(off, n)
            if len(d) == n:
                return d
        except DiskError as e:
            dbg("read error @%d attempt %d: %s" % (off, attempt + 1, e))
        except Exception as e:
            dbg("read error @%d attempt %d: %s" % (off, attempt + 1, e))
        time.sleep(0.02)
    return None


def _img_progress(done, total, bad):
    if QUIET:
        return
    sys.stdout.write("\r    imaging %5.1f%%  %s / %s%s   " % (
        100.0 * done / total, human(done), human(total),
        "  bad=%s" % human(bad) if bad else ""))
    sys.stdout.flush()


# =============================================================================
# SECTION 15 — Windows integration
# =============================================================================

def win_disk_index_from_path(path):
    m = re.search(r"PhysicalDrive(\d+)$", str(path), re.I)
    return int(m.group(1)) if m else None


def win_set_offline(index, offline=True):
    """Take a disk offline so its volumes stop blocking raw writes."""
    if not IS_WIN or index is None:
        return False
    rc, so, se = ps("Set-Disk -Number %d -IsOffline $%s -ErrorAction Stop" %
                    (index, "true" if offline else "false"))
    if rc != 0:
        script = "select disk %d\r\n%s\r\nexit\r\n" % (
            index, "offline disk" if offline else "online disk")
        with tempfile.NamedTemporaryFile(mode="w", prefix="dd_diskpart_", suffix=".txt", delete=False) as fh:
            f = fh.name
            fh.write(script)
            fh.flush()
            os.fsync(fh.fileno())
        rc2, so2, se2 = run_cmd(["diskpart", "/s", f])
        return rc2 == 0
    return True


def win_set_readonly(index, ro=False):
    if not IS_WIN or index is None:
        return False
    rc, _, _ = ps("Set-Disk -Number %d -IsReadOnly $%s" %
                  (index, "true" if ro else "false"))
    return rc == 0


def win_rescan():
    if not IS_WIN:
        return False
    rc, _, _ = ps("Update-HostStorageCache")
    if rc != 0:
        with tempfile.NamedTemporaryFile(mode="w", prefix="dd_rescan_", suffix=".txt", delete=False) as fh:
            f = fh.name
            fh.write("rescan\r\nexit\r\n")
            fh.flush()
            os.fsync(fh.fileno())
        rc, _, _ = run_cmd(["diskpart", "/s", f])
    return rc == 0


def win_lock_dismount(letter):
    r"""FSCTL_LOCK_VOLUME + FSCTL_DISMOUNT_VOLUME on \\.\X: — returns a handle."""
    if not IS_WIN:
        return None
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    FILE_SHARE = 0x00000003
    OPEN_EXISTING = 3
    FSCTL_LOCK_VOLUME = 0x00090018
    FSCTL_DISMOUNT_VOLUME = 0x00090020
    k = ctypes.windll.kernel32
    k.CreateFileW.restype = ctypes.c_void_p               # 64-bit safe handle
    raw = k.CreateFileW(r"\\.\%s:" % letter.rstrip(":"),
                        GENERIC_READ | GENERIC_WRITE, FILE_SHARE, None,
                        OPEN_EXISTING, 0, None)
    if not raw or raw == ctypes.c_void_p(-1).value:
        return None
    h = ctypes.c_void_p(raw)
    ret = ctypes.c_uint32()
    k.DeviceIoControl(h, FSCTL_LOCK_VOLUME, None, 0, None, 0, ctypes.byref(ret), None)
    k.DeviceIoControl(h, FSCTL_DISMOUNT_VOLUME, None, 0, None, 0, ctypes.byref(ret), None)
    return h


def win_close_handle(h):
    if IS_WIN and h:
        try:
            ctypes.windll.kernel32.CloseHandle(h)
        except Exception:
            pass


def run_chkdsk(letter, fix=True):
    if fix:
        raise DiskError("Source mutation must go through the audited external-action gate")
    if not IS_WIN or not re.fullmatch(r"[A-Za-z]:?", letter):
        return EXIT_ARG
    rc, so, se = run_cmd(["chkdsk", letter.rstrip(":") + ":"], timeout=3600)
    out(so)
    out(se)
    return rc


# refsutil's ReFS-version ceiling is tied to the Windows build it ships with,
# not to the tool version string, and Microsoft does not publish a lookup
# table. Rather than guess a mapping that will go stale, this parses the
# ceiling straight out of refsutil's own error text — it states its own limit
# plainly ("This utility supports versions up to 3.9") whenever it refuses a
# newer volume.
REFSUTIL_UNSUPPORTED_RE = re.compile(
    r"unsupported ReFS version.*?up to\s+(\d+\.\d+)", re.IGNORECASE | re.DOTALL)
REFSUTIL_VOLUME_VERSION_RE = re.compile(
    r"ReFS version:\s*(\d+\.\d+)", re.IGNORECASE)


def parse_refsutil_version_mismatch(output):
    """Detect refsutil's 'volume is a newer ReFS version than I support' error.

    Returns {"volume_version": "3.14", "max_supported": "3.9"} or None. Both
    fields are read from refsutil's own text, which is why this file never
    hard-codes a version table.
    """
    m2 = REFSUTIL_UNSUPPORTED_RE.search(output)
    if not m2:
        return None
    m1 = REFSUTIL_VOLUME_VERSION_RE.search(output)
    return {"volume_version": m1.group(1) if m1 else None,
            "max_supported": m2.group(1)}


def run_refsutil(letter, work_dir, target_dir, mode="-QA"):
    """refsutil salvage <mode> <volume> <working dir> <target dir> [-x]

    The Windows syntax takes THREE positional arguments. The working directory
    must be on a different, healthy volume with room for the scan metadata, and
    the target directory is where recovered files are written. Neither may sit
    on the damaged volume.

    IMPORTANT — version ceiling: refsutil can only salvage a ReFS volume whose
    on-disk version is at or below the ceiling built into that copy of
    refsutil (itself tied to the Windows build it shipped with, e.g. build
    11070 tops out at 3.9). A volume formatted by a newer Windows — ReFS 3.14
    is Server 2025 / recent Windows 11 — will be refused outright with "volume
    does not contain a recognized file system", even though the volume is
    intact and refsutil correctly identified its version just one line above
    that message. This is a tool-version mismatch, not filesystem corruption,
    and no retry or -FA fixes it; only running refsutil from a Windows build
    that supports that ReFS version will.
    """
    if not IS_WIN:
        warn("refsutil فقط روی ویندوز موجود است.")
        return 1
    vol = "%s:" % letter.rstrip(":")
    if not re.fullmatch(r"[A-Za-z]:?", letter):
        raise DiskError("invalid source drive letter")
    source_volume = safety.volume_identity(vol + "\\")
    for d in (work_dir, target_dir):
        if safety.volume_identity(d) == source_volume:
            raise DiskError("working/destination volume aliases the source")
        os.makedirs(d, exist_ok=True)
        if os.path.splitdrive(os.path.abspath(d))[0].upper() == vol.upper():
            err("پوشه کاری/مقصد نباید روی همان ولوم آسیب‌دیده باشد: %s" % d)
            return 2
    args = ["refsutil", "salvage", mode, vol, work_dir, target_dir, "-x"]
    info("running: %s" % " ".join(args))
    if mode == "-QA":
        info("حالت QA سریع است ولی همه فایل‌ها را پیدا نمی‌کند. اگر نتیجه کم "
             "بود، -FA (فول) را اجرا کن: --refs-mode FA")
    rc, so, se = run_cmd(args, timeout=7200)
    out(so[-4000:])
    if se.strip():
        warn(se[-1000:])
    mismatch = parse_refsutil_version_mismatch(so + "\n" + se)
    if mismatch:
        print_refsutil_version_mismatch(mismatch)
        return 10
    return rc


def print_refsutil_version_mismatch(m):
    out("")
    out(C.w(C.BOLD + C.RED, " عدم تطابق نسخه refsutil — نه خرابی فایل‌سیستم"))
    if m.get("volume_version"):
        out("   نسخه ReFS روی ولوم : %s" % m["volume_version"])
    out("   سقف نسخه این refsutil : %s" % m["max_supported"])
    out("")
    out("   این خطا یعنی خود refsutil ولوم را شناخت و نسخه‌اش را درست خواند —")
    out("   فقط چون نسخه فایل‌سیستم از سقف پشتیبانی این نسخه refsutil بالاتر")
    out("   است رد شد. ولوم لزوماً خراب نیست. تکرار دستور یا حالت -FA این را")
    out("   حل نمی‌کند؛ سقف نسخه به build ویندوزی که refsutil از آن آمده")
    out("   وابسته است، نه به پرچم‌های خط فرمان.")
    out("")
    out("   راه‌حل‌ها:")
    out("      1) دیسک را روی ویندوزی جدیدتر Attach کن که همین نسخه ReFS را")
    out("         می‌شناسد (نسخه 3.14 با Windows Server 2025 / بیلدهای اخیر")
    out("         ویندوز 11 می‌آید) و همان‌جا refsutil را اجرا کن.")
    out("      2) ابزار بازیابی مستقل که به درایور ReFS ویندوز وابسته نیست")
    out("         (مثل ReclaiMe یا UFS Explorer) و از پشتیبانی ReFS 3.x جدید")
    out("         را روی یک ایمیج/کپی اجرا کن.")
    out("      3) اگر این repository ویم است، Veeam Support ابزار داخلی برای")
    out("         خواندن مستقیم فایل‌های .vbk دارد، مستقل از refsutil.")
    out("")




# =============================================================================
# SECTION 16 — Hard safety gate + execution
# =============================================================================

def confirm(prompt=None, assume_yes=False):
    if assume_yes:
        return True
    try:
        return input(prompt or T("confirm_type")).strip() == "YES"
    except (EOFError, KeyboardInterrupt):
        return False


def privilege_gate(disk, args):
    try:
        safety.absolute_guard(sys.modules[__name__], disk)
        return True
    except core.SafetyError as e:
        err(str(e))
        return False


def print_blocked(action, reasons):
    out("")
    out(C.w(C.BOLD + C.RED, " REPAIR BLOCKED: %s" % action))
    for rr in reasons:
        out("   " + C.w(C.RED, "• ") + rr)
    out("")
    info("هیچ بایتی نوشته نشد. برای دیدن جزئیات شواهد: --explain")


def execute_action(disk, r, args, action_key):
    return safety.execute(sys.modules[__name__], disk, r, args, action_key)


def run_external(disk, r, args, key):
    return safety.external(sys.modules[__name__], disk, r, args, key)


# =============================================================================
# SECTION 17 — Wizard
# =============================================================================

class Cancel(Exception):
    pass


class Back(Exception):
    pass


def ask(prompt, choices=None, default=None, helptext=""):
    while True:
        suffix = " [%s]" % default if default is not None else ""
        try:
            a = input("%s%s  (%s) > " % (prompt, suffix, T("back_hint"))).strip()
        except (EOFError, KeyboardInterrupt):
            raise Cancel()
        if a == "" and default is not None:
            a = str(default)
        if a.lower() == "q":
            raise Cancel()
        if a.lower() == "b":
            raise Back()
        if a == "?":
            out(helptext or "-")
            continue
        if choices and a not in choices:
            warn("گزینه معتبر: %s" % ", ".join(choices))
            continue
        return a


def wizard(args):
    state = "target"
    ctx = {"args": args, "disk": None, "scan": None, "plans": []}
    history = []
    while state != "done":
        try:
            nxt = WIZ_STEPS[state](ctx)
            history.append(state)
            state = nxt
        except Back:
            if history:
                state = history.pop()
            else:
                out(T("cancelled"))
                return EXIT_CANCEL
        except Cancel:
            out(T("cancelled"))
            return EXIT_CANCEL
        except DiskError as e:
            err(str(e))
            if not history:
                return EXIT_ERR
            state = history.pop()
    return EXIT_OK


def _w_target(ctx):
    args = ctx["args"]
    if not args.disk:
        disks = list_disks()
        if disks:
            out("")
            out(C.w(C.BOLD, " دیسک‌های موجود"))
            for d in disks:
                out("   [%s] %-28s %10s  style=%-8s offline=%s  %s" % (
                    d["index"], (d["model"] or "?")[:28], human(d["size"]),
                    d["style"] or "?", d["offline"],
                    ",".join([str(v.get("Letter")) for v in d.get("volumes", [])
                              if v.get("Letter")])))
        while True:
            sel = ask("شماره دیسک یا مسیر فایل ایمیج",
                      helptext="مثال: 2  یا  D:\\img\\flat.img  یا  /dev/sdb")
            if sel:
                break
            warn("خالی نگذار.")
        args.disk = sel
    if ctx["disk"]:
        ctx["disk"].close()
    path = resolve_target(args.disk)
    ctx["disk"] = RawDisk(path, sector_size=args.sector_size,
                          base_offset=args.offset, writable=False)
    ok("target: %s  %s  sector=%d" % (path, human(ctx["disk"].size), ctx["disk"].sector))
    return "scan"


def _w_scan(ctx):
    global EXPLAIN
    args = ctx["args"]
    mode = ask("نوع اسکن؟ 1=سریع  2=عمیق  3=عمیق+توضیح شواهد",
               choices=["1", "2", "3"], default="1",
               helptext="اسکن سریع فقط جدول‌ها و آفست‌های متداول را می‌خواند. "
                        "گزینه 3 جدول کامل شواهد هر کاندید را هم چاپ می‌کند.")
    if mode == "3":
        EXPLAIN = True
    ctx["scan"] = scan(ctx["disk"], deep=(mode in ("2", "3")),
                       deep_step=args.deep_step, deep_limit=args.deep_limit,
                       time_budget=args.time_budget)
    print_report(ctx["scan"])
    if args.json:
        _write_json(args.json, ctx["scan"])
    return "plan"


def _w_plan(ctx):
    d, r = ctx["disk"], ctx["scan"]
    ctx["plans"] = [p for p in suggest_plans(d, r) if p["action"] != "__none__"]
    print_plans(d, r, suggest_plans(d, r))
    opts = [str(i) for i in range(1, len(ctx["plans"]) + 1)] + \
           ["m", "i", "e", "t", "r", "x"]
    out("   m) اقدام دستی   i) ایمیج   e) توضیح شواهد   t) triage   "
        "r) اسکن دوباره   x) خروج")
    sel = ask("کدام؟", choices=opts, default="x",
              helptext="عدد = همان طرح. اقدام‌های [BLOCKED] اجرا نمی‌شوند ولی "
                       "دلیل دقیقشان چاپ می‌شود.")
    if sel == "x":
        raise Cancel()
    if sel == "r":
        raise Back()
    if sel == "e":
        print_evidence(r)
        return "plan"
    if sel == "t":
        run_triage(d, r, ctx["args"])
        return "plan"
    if sel == "i":
        p = ask("مسیر فایل ایمیج خروجی", default="disk_image.img")
        make_image(d, p, limit=ctx["args"].image_limit,
                   retries=ctx["args"].image_retries, fill=ctx["args"].image_fill)
        return "plan"
    if sel == "m":
        keys = list(ACTION_BUILDERS.keys()) + list(EXTERNAL_ACTIONS)
        for i, k in enumerate(keys, 1):
            out("   %2d) %-22s [%s]" % (i, k, probe_gate(d, r, k)))
        s2 = ask("شماره اقدام", choices=[str(i) for i in range(1, len(keys) + 1)])
        ctx["chosen"] = {"action": keys[int(s2) - 1], "part": None}
    else:
        ctx["chosen"] = ctx["plans"][int(sel) - 1]
    return "confirm"


def _w_confirm(ctx):
    args, ch = ctx["args"], ctx["chosen"]
    if ch.get("part"):
        args.part = ch["part"]
    if ch["action"] in ("vbr-restore", "vbr-restore-reverse") and not args.part:
        args.part = int(ask("شماره پارتیشن هدف"))
    args.apply = False
    rc = execute_action(ctx["disk"], ctx["scan"], args, ch["action"])
    if rc == EXIT_BLOCKED:
        ask("Enter برای بازگشت", default="")
        raise Back()
    go = ask("اعمال شود؟ y=بله  n=خیر", choices=["y", "n"], default="n",
             helptext="با y واقعاً نوشته می‌شود؛ Journal قبل از نوشتن ساخته "
                      "می‌شود تا برگشت همیشه ممکن باشد.")
    if go == "n":
        raise Back()
    gate = probe_gate(ctx["disk"], ctx["scan"], ch["action"], args.part)
    if gate == GATE_INFERRED and not args.allow_inferred:
        warn("این اقدام ساختار را سنتز می‌کند.")
        if ask("تایید می‌کنی که ساختار سنتز شود؟ y/n", choices=["y", "n"],
               default="n") != "y":
            raise Back()
        args.allow_inferred = True
    args.apply = True
    execute_action(ctx["disk"], ctx["scan"], args, ch["action"])
    args.apply = False
    ctx["scan"] = scan(ctx["disk"])
    return "plan"


WIZ_STEPS = {"target": _w_target, "scan": _w_scan, "plan": _w_plan,
             "confirm": _w_confirm}


def _write_json(path, sc):
    _atomic_write_json(path, sc.to_dict())
    ok("JSON report: %s" % path)


# =============================================================================
# SECTION 18 — Self-test
# =============================================================================
# The structures below are built from the ON-DISK SPECIFICATION, using
# constants deliberately chosen to differ from any value the parser could
# accidentally hard-code. For example the FAT32 image uses BPB_FSInfo=1 and
# BPB_BkBootSec=17 and puts a decoy 6 at offset 0x34, so a parser that reads
# the wrong offset fails the test instead of passing by coincidence.
# =============================================================================

TEST_FAT32_FSINFO = 1
TEST_FAT32_BKBOOT = 17          # NOT the usual 6
TEST_FAT32_DECOY_AT_0x34 = 6    # what a buggy parser would read
TEST_NTFS_SERIAL = 0x0BADC0FFEE123456
TEST_EXFAT_SERIAL = 0xFEEDFACE


def _t_exfat_checksum(data, bps):
    """Independent restatement of the exFAT VBR checksum, per the spec text."""
    c = 0
    for i in range(11 * bps):
        if i in (106, 107, 112):
            continue
        c = ((0x80000000 if (c & 1) else 0) + (c >> 1) + data[i]) & 0xFFFFFFFF
    return c


def _mk_ntfs_vbr(total_sectors, bps=512, spc=8, serial=TEST_NTFS_SERIAL, hidden=0):
    b = bytearray(bps)
    b[0:3] = b"\xEB\x52\x90"
    b[3:11] = b"NTFS    "
    struct.pack_into("<H", b, 0x0B, bps)
    b[0x0D] = spc
    struct.pack_into("<H", b, 0x0E, 0)          # reserved sectors must be 0
    b[0x15] = 0xF8
    struct.pack_into("<H", b, 0x18, 63)
    struct.pack_into("<H", b, 0x1A, 255)
    struct.pack_into("<I", b, 0x1C, hidden)
    struct.pack_into("<Q", b, 0x28, total_sectors - 1)
    clusters = max(4, (total_sectors - 1) // spc)
    struct.pack_into("<Q", b, 0x30, 4)
    struct.pack_into("<Q", b, 0x38, clusters // 2)
    struct.pack_into("<Q", b, 0x48, serial)
    b[510:512] = b"\x55\xAA"
    return bytes(b)


def _mk_fat32_vbr(total_sectors, bps=512, spc=8, hidden=0, label="TESTFAT32  ",
                  bk=TEST_FAT32_BKBOOT, fsinfo=TEST_FAT32_FSINFO):
    b = bytearray(bps)
    b[0:3] = b"\xEB\x58\x90"
    b[3:11] = b"MSDOS5.0"
    struct.pack_into("<H", b, 0x0B, bps)
    b[0x0D] = spc
    struct.pack_into("<H", b, 0x0E, 32)         # reserved sectors
    b[0x10] = 2                                  # num FATs
    struct.pack_into("<H", b, 0x11, 0)
    struct.pack_into("<H", b, 0x13, 0)
    b[0x15] = 0xF8
    struct.pack_into("<H", b, 0x16, 0)
    struct.pack_into("<I", b, 0x1C, hidden)
    struct.pack_into("<I", b, 0x20, total_sectors)
    struct.pack_into("<I", b, 0x24, 512)         # FATSz32
    struct.pack_into("<I", b, 0x2C, 2)
    struct.pack_into("<H", b, 0x30, fsinfo)      # BPB_FSInfo
    struct.pack_into("<H", b, 0x32, bk)          # BPB_BkBootSec  (the real one)
    b[0x34] = TEST_FAT32_DECOY_AT_0x34           # decoy for a buggy parser
    struct.pack_into("<I", b, 0x43, 0xAABBCCDD)
    b[0x47:0x52] = label.encode()[:11].ljust(11)
    b[0x52:0x5A] = b"FAT32   "
    b[510:512] = b"\x55\xAA"
    return bytes(b)


def _mk_exfat_region(vol_sectors, part_off, bps=512):
    """Build the full 12-sector exFAT VBR region including its checksum."""
    b = bytearray(bps)
    b[0:3] = b"\xEB\x76\x90"
    b[3:11] = b"EXFAT   "
    struct.pack_into("<Q", b, 0x40, part_off)
    struct.pack_into("<Q", b, 0x48, vol_sectors)
    struct.pack_into("<I", b, 0x50, 128)
    struct.pack_into("<I", b, 0x54, 512)
    struct.pack_into("<I", b, 0x58, 2048)
    struct.pack_into("<I", b, 0x5C, max(16, vol_sectors // 8))
    struct.pack_into("<I", b, 0x60, 5)
    struct.pack_into("<I", b, 0x64, TEST_EXFAT_SERIAL)
    struct.pack_into("<H", b, 0x68, 0x0100)
    b[0x6C] = {512: 9, 1024: 10, 2048: 11, 4096: 12}[bps]
    b[0x6D] = 3
    b[510:512] = b"\x55\xAA"
    region = bytearray(bytes(b))
    for i in range(1, 9):                       # extended boot sectors
        ext = bytearray(bps)
        ext[bps - 4:bps] = b"\x00\x00\x55\xAA"
        region += ext
    region += bytearray(bps)                    # OEM parameters
    region += bytearray(bps)                    # reserved
    cs = _t_exfat_checksum(bytes(region), bps)
    region += struct.pack("<I", cs) * (bps // 4)
    return bytes(region)


def _mk_refs_vbr(total_sectors, bps=512, spc=128, major=3, minor=14):
    """ReFS volume header, using the layout observed on a real ReFS 3.14 disk.

    Note the identifier sits at 0x10, i.e. MustBeZero is five bytes, not four.
    Several published layouts say 0x0F; the parser locates FSRS by search so it
    survives either, but the test must model the real thing.
    """
    b = bytearray(bps)
    b[0:3] = b"\x00\x00\x00"
    b[3:11] = b"ReFS\x00\x00\x00\x00"      # FileSystemName
    b[0x0B:0x10] = b"\x00" * 5              # MustBeZero (5 bytes)
    b[0x10:0x14] = b"FSRS"                  # Identifier
    struct.pack_into("<H", b, 0x14, 0x50)   # header length
    struct.pack_into("<H", b, 0x16, 0)      # checksum
    struct.pack_into("<Q", b, 0x18, total_sectors)
    struct.pack_into("<I", b, 0x20, bps)
    struct.pack_into("<I", b, 0x24, spc)
    b[0x28] = major
    b[0x29] = minor
    return bytes(b)


def _put_refs(img, start, vol_sectors, part_sectors=None):
    """Write a ReFS volume: header at the start, a copy in its last sector,
    superblock structures near the end, checkpoints spread through it."""
    hdr = _mk_refs_vbr(vol_sectors)
    img.put(start, hdr)
    end = start + vol_sectors                      # exclusive
    img.put(end - 1, hdr)                          # volume header copy
    for back in (384, 256):
        img.put(end - back, b"SUPB" + bytes(508))
    step = max(2048, vol_sectors // 40)
    for lba in range(start + step, end - 1024, step):
        img.put(lba, b"CHKP" + bytes(508))
    return hdr


def _mk_ext4_sb(blocks=16384, bsz=1024, label="testext4"):
    sb = bytearray(1024)
    struct.pack_into("<I", sb, 0x04, blocks)
    struct.pack_into("<I", sb, 0x18, {1024: 0, 2048: 1, 4096: 2}[bsz])
    struct.pack_into("<H", sb, 0x38, 0xEF53)
    struct.pack_into("<I", sb, 0x60, 0x40)
    sb[0x68:0x78] = bytes(range(16))
    sb[0x78:0x78 + len(label)] = label.encode()
    return bytes(sb)


class _Img(object):
    def __init__(self, path, size, sector=512):
        self.path, self.size, self.sector = path, size, sector
        with open(path, "wb") as f:
            f.truncate(size)

    def put(self, lba, data):
        with open(self.path, "r+b") as f:
            f.seek(lba * self.sector)
            f.write(data)

    def zero(self, lba, count=1):
        self.put(lba, bytes(count * self.sector))

    def read(self, lba, count=1):
        with open(self.path, "rb") as f:
            f.seek(lba * self.sector)
            return f.read(count * self.sector)

    def sha(self):
        h = hashlib.sha256()
        with open(self.path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()


def _put_ntfs(img, start, sectors, bps=512):
    vbr = _mk_ntfs_vbr(sectors, bps=bps, hidden=start)
    img.put(start, vbr)
    img.put(start + sectors - 1, vbr)     # mirror = last sector of the volume
    return vbr


def _put_fat32(img, start, sectors):
    vbr = _mk_fat32_vbr(sectors, hidden=start)
    img.put(start, vbr)
    img.put(start + TEST_FAT32_BKBOOT, vbr)
    return vbr


def _put_exfat(img, start, sectors):
    region = _mk_exfat_region(sectors, start)
    img.put(start, region)                # sectors 0..11
    img.put(start + 12, region)           # sectors 12..23 mirror
    return region


def _fake_args(**kw):
    ns = argparse.Namespace(
        disk=None, sector_size=None, offset=0, list=False, scan=False,
        deep=False, deep_step=MIB, deep_limit=0, time_budget=0, wizard=False,
        plan=False, apply=False, allow_inferred=False, action=None, undo=None,
        inspect=None, check_journals=False, self_test=False, explain=False,
        yes=True, force=False, offline=False, part=None, letter=None,
        backup_dir=tempfile.mkdtemp(prefix="ddbk_"), image_out=None,
        image_limit=0, image_retries=3, image_fill="zero", json=None, log=None,
        lang="fa", no_color=True, quiet=True, verbose=False, refs_out=None,
        refs_work=None, refs_mode="QA", help_full=False,
        deep_ignore_table=False, triage=False, triage_all=False,
        triage_samples=320, triage_sample_kib=64, triage_tail_mib=512,
        triage_edge_gib=16, auto=False, all=False, auto_out=None,
        auto_deep_seconds=600, triage_head_gib=8, triage_head_samples=128,
        baseline=None, find_name=None, find_name_file=None, find_limit=0, find_max_hits=50,
        dump_range=None, dump_out="dump.bin", dump_strings_min=6,
        dump_raw_strings=False, find_vbm=False, find_vbm_window=512 * KIB,
        find_vbm_max_hits=20, carve_vbk=None, carve_out="carved.bin",
        locate_vbk=None, locate_align=65536, locate_radius_gib=2.0,
        locate_verify=None, locate_verify_top_n=40, locate_probe_mib=8,
        locate_verify_file=None)
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


def _scan_file(path, deep=False, step=512, sector=None):
    d = RawDisk(path, sector_size=sector, writable=False)
    return d, scan(d, deep=deep, deep_step=step)


def _apply(path, action_key, part=None, backup_dir=None, deep=True,
           allow_inferred=True, sector=None):
    args = _fake_args(apply=True, part=part, allow_inferred=allow_inferred,
                      backup_dir=backup_dir or tempfile.mkdtemp(prefix="ddbk_"))
    d = RawDisk(path, sector_size=sector, writable=False)
    try:
        r = scan(d, deep=deep, deep_step=512)
        rc = execute_action(d, r, args, action_key)
        js = sorted([os.path.join(args.backup_dir, f)
                     for f in os.listdir(args.backup_dir) if f.startswith("journal_")])
        return rc, (js[-1] if js else None)
    finally:
        d.close()


def _build(path, action_key, part=None):
    """Build an action without applying; returns (action, blocked_reasons)."""
    d = RawDisk(path, writable=False)
    try:
        r = scan(d, deep=True, deep_step=512)
        try:
            return ACTION_BUILDERS[action_key](d, r, _fake_args(part=part)), None
        except Blocked as b:
            return None, b.reasons
    finally:
        d.close()


def self_test():
    # Field scenarios are preserved byte-for-byte in the reference fixture;
    # the harness also runs those scenarios against the current forensic engine
    # and runs the v2 write-safety and fault-injection tests on synthetic images.
    from tests.run_regressions import run
    return run()


# =============================================================================
# SECTION 19b — One-shot mode  (--auto)
# =============================================================================
# Everything in a single run, with no decisions to make: enumerate, scan, go
# deep only when the partition table is missing or suspect, triage every volume
# that is not provably healthy, and write one text report plus one JSON file.
# Read-only from start to finish.
# =============================================================================

def _disk_verdict(disk, r, tri):
    """One conclusion per disk."""
    if r.blockers:
        keys = [k for k, _ in r.blockers]
        if "container" in keys:
            return ("هدف دیسک خام نیست", C.RED,
                    ["این فایل یک کانتینر است. دیسک Attach شده را هدف بگیر."])
        return ("blocker سراسری فعال", C.RED,
                ["%s" % w for _, w in r.blockers])
    real = [p for p in r.parts if not type_expects_no_fs(p)]
    if not real and not r.carved:
        return ("هیچ ولومی شناسایی نشد", C.RED,
                ["با --deep --deep-step 512 دوباره اسکن کن."])
    bad = [p for p in real if not (p.ev and p.ev.level == "strong" and p.fs)]
    if not bad:
        return ("سالم", C.GREEN, ["هیچ اقدامی لازم نیست."])
    lines = []
    worst = None
    for t in (tri or []):
        v = t.get("verdict") or {}
        lines.append("پارتیشن #%d: %s" % (t["num"], v.get("label", "?")))
        for s in v.get("next_steps", [])[:2]:
            lines.append("   → " + s)
        if worst is None or v.get("color") == C.RED:
            worst = v
    label = (worst or {}).get("label", "نیازمند بررسی")
    color = (worst or {}).get("color", C.YELLOW)
    return ("%d ولوم مشکل‌دار — %s" % (len(bad), label), color, lines)


def auto_one(path, args):
    """Full pipeline for a single target. Returns a summary dict."""
    out("")
    out(C.w(C.BOLD, "#" * 78))
    out(C.w(C.BOLD, "# %s" % path))
    out(C.w(C.BOLD, "#" * 78))
    summary = {"target": path}
    try:
        disk = RawDisk(path, sector_size=args.sector_size,
                       base_offset=args.offset, writable=False)
    except DiskError as e:
        err(str(e))
        summary.update(error=str(e), verdict="باز نشد")
        return summary
    try:
        r = scan(disk)
        # go deep only when the table itself failed to describe the disk
        need_deep = (not r.parts) or r.scheme.startswith("RAW") or \
                    r.scheme.startswith("GPT (protective")
        suspect_table = any(k in r.blocker_keys()
                            for k in ("mbr_out_of_range", "geometry_mismatch"))
        if need_deep:
            info("جدول پارتیشن ولوم‌ها را توصیف نمی‌کند — اسکن عمیق (سقف %ds)"
                 % args.auto_deep_seconds)
            r = scan(disk, deep=True, deep_step=args.deep_step,
                     time_budget=args.auto_deep_seconds,
                     ignore_table=suspect_table)
        print_report(r)
        tri = run_triage(disk, r, args)
        label, color, lines = _disk_verdict(disk, r, tri)
        out("")
        out(C.w(C.BOLD, " ══ نتیجه این دیسک ══"))
        out("   " + C.w(color, label))
        for ln in lines:
            out("   " + ln)
        plans = suggest_plans(disk, r)
        print_plans(disk, r, plans)
        safety.persist_report(sys.modules[__name__], disk, r, args, triage=tri)
        summary.update(
            size=disk.size, sector=disk.sector, scheme=r.scheme,
            partitions=len(r.parts), carved=len(r.carved),
            blockers=r.blocker_keys(), verdict=label,
            verdict_lines=lines,
            plans=[p["action"] for p in plans if p["action"] != "__none__"],
            report=r.to_dict(), triage=tri)
        return summary
    finally:
        disk.close()


def auto_run(args):
    """--auto : one command, every answer, nothing written."""
    global REPORTFILE, LOGFILE
    ts = str(uuid.uuid4())
    txt = args.auto_out or ("diskdoctor_report_%s.txt" % ts)
    jsn = os.path.splitext(txt)[0] + ".json"
    targets = []
    if args.all or not args.disk:
        disks = list_disks()
        if not disks:
            err("هیچ دیسکی شمرده نشد (ویندوز: Run as Administrator).")
            return EXIT_NOTFOUND
        out("")
        out(C.w(C.BOLD, " دیسک‌های یافت‌شده"))
        for d in disks:
            letters = ",".join([str(v.get("Letter")) for v in d.get("volumes", [])
                                if v.get("Letter")])
            out("   [%s] %12s  %-8s %s %s" % (
                d["index"], human(d["size"]), d["style"] or "?",
                (d["model"] or "")[:32], ("[" + letters + "]") if letters else ""))
        targets = [d["path"] for d in disks]
        if not args.all:
            targets = [resolve_target(args.disk)] if args.disk else targets
    else:
        targets = [resolve_target(args.disk)]

    # Validate every source/output relationship before opening any output.
    try:
        for target in targets:
            with RawDisk(target, sector_size=args.sector_size, writable=False) as source:
                for destination in (txt, jsn, args.log, getattr(args, "state_dir", "DiskDoctor")):
                    if destination:
                        safety.ensure_destination(sys.modules[__name__], source, destination)
        REPORTFILE = open(txt, "x", encoding="utf-8")
        if args.log and LOGFILE is None:
            LOGFILE = open(args.log, "x", encoding="utf-8")
    except (core.SafetyError, DiskError, OSError) as e:
        err(str(e))
        if REPORTFILE:
            REPORTFILE.close()
            REPORTFILE = None
        return EXIT_BLOCKED

    out("")
    info("حالت auto: فقط خواندن. %d هدف. گزارش در %s" % (len(targets), txt))
    started = time.time()

    # Pass 1: a quick structural scan of everything, so a provably healthy
    # volume can be used as the control for the damaged ones.
    if not getattr(args, "_control", None) and len(targets) > 1:
        info("پاس اول: شناسایی یک ولوم سالم به‌عنوان کنترل ...")
        quick = []
        for t in targets:
            try:
                dq = RawDisk(t, sector_size=args.sector_size, writable=False)
            except DiskError:
                continue
            try:
                quick.append((t, scan(dq)))
            except Exception:
                pass
            finally:
                dq.close()
        ctl = pick_control(quick)
        if ctl:
            args._control = ctl
            ok("کنترل: %s  پارتیشن @LBA %d  (%s)"
               % (ctl["path"], ctl["start"], ctl["fs"]))
        else:
            warn("هیچ ولوم سالمی برای کنترل پیدا نشد؛ مقایسه انجام نمی‌شود.")

    summaries = []
    for t in targets:
        try:
            summaries.append(auto_one(t, args))
        except KeyboardInterrupt:
            warn("متوقف شد توسط کاربر.")
            break
        except Exception as e:
            err("%s: %s" % (t, e))
            summaries.append({"target": t, "error": str(e), "verdict": "خطا"})

    out("")
    out(C.w(C.BOLD, "=" * 78))
    out(C.w(C.BOLD, " خلاصه نهایی   (%.0f ثانیه)" % (time.time() - started)))
    out(C.w(C.BOLD, "=" * 78))
    for s in summaries:
        v = s.get("verdict", "?")
        col = C.GREEN if v == "سالم" else (C.RED if "مشکل" in v or "خطا" in v
                                           or "نشد" in v else C.YELLOW)
        name = str(s["target"]).rstrip("\\/").split("\\")[-1].split("/")[-1] \
            or str(s["target"])
        out("   %-26s %10s  %s" % (
            name[:26],
            human(s.get("size")) if s.get("size") else "-",
            C.w(col, v)))
        for ln in s.get("verdict_lines", [])[:3]:
            out("        " + ln)
    out("")
    out(" گزارش متنی : %s" % txt)
    out(" گزارش JSON : %s" % jsn)
    out(" هیچ بایتی روی هیچ دیسکی نوشته نشد.")

    doc = {"tool": "DiskDoctor", "version": VERSION,
           "generated": datetime.datetime.now().isoformat(timespec="seconds"),
           "elapsed_sec": round(time.time() - started, 1),
           "disks": summaries}
    try:
        _atomic_write_json(jsn, doc)
    except Exception as e:
        err("cannot write JSON: %s" % e)
    if REPORTFILE:
        try:
            REPORTFILE.close()
        except Exception:
            pass
        REPORTFILE = None
    return EXIT_OK

# =============================================================================
# SECTION 19 — CLI
# =============================================================================

def build_parser():
    p = argparse.ArgumentParser(
        prog="diskdoctor.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="DiskDoctor %s — forensic scanner + evidence-based repair" % VERSION,
        epilog="راهنمای کامل فارسی:  python diskdoctor.py --help-full")

    g = p.add_argument_group("هدف")
    g.add_argument("--list", action="store_true", help="فهرست دیسک‌های سیستم")
    g.add_argument("--disk", help=r"شماره دیسک، \\.\PhysicalDriveN، /dev/sdX یا فایل ایمیج")
    g.add_argument("--sector-size", type=int, default=None, help="اندازه سکتور (512/4096)")
    g.add_argument("--offset", type=int, default=0, help="آفست شروع داخل فایل")

    g = p.add_argument_group("یک‌ضرب")
    g.add_argument("--auto", action="store_true",
                   help="همه‌چیز در یک اجرا: اسکن، اسکن عمیق در صورت نیاز، "
                        "triage هر ولوم مشکوک، نتیجه‌گیری، و نوشتن گزارش "
                        "متنی و JSON. فقط خواندن.")
    g.add_argument("--all", action="store_true",
                   help="روی همه دیسک‌های سیستم اجرا کن")
    g.add_argument("--auto-out", metavar="PATH",
                   help="مسیر گزارش متنی (پیش‌فرض diskdoctor_report_<time>.txt)")
    g.add_argument("--auto-deep-seconds", type=int, default=600,
                   help="سقف زمان اسکن عمیق هر دیسک در حالت auto (پیش‌فرض 600)")

    g = p.add_argument_group("اسکن")
    g.add_argument("--scan", action="store_true", help="اسکن و گزارش (فقط خواندن)")
    g.add_argument("--deep", action="store_true", help="اسکن عمیق امضایی")
    g.add_argument("--deep-step", type=int, default=MIB, help="فیلتر هم‌ترازی کاندیدها")
    g.add_argument("--deep-limit", type=int, default=0, help="سقف حجم اسکن عمیق")
    g.add_argument("--time-budget", type=int, default=0, help="سقف زمان اسکن عمیق")
    g.add_argument("--explain", action="store_true",
                   help="چاپ جدول کامل شواهد هر کاندید")
    g.add_argument("--find-name", metavar="TEXT",
                   help="جستجوی یک نام فایل در بایت‌های خام دیسک، مستقل از "
                        "فایل‌سیستم. برای پاسخ به «آیا این فایل روی این دیسک "
                        "بوده؟» وقتی ساختار فایل‌سیستم نابود شده. فقط خواندن.")
    g.add_argument("--find-name-file", metavar="PATH",
                   help="متن --find-name را از این فایل بخوان (UTF-8، خط اول، "
                        "BOM خودکار حذف می‌شود). برای متنی که کوتیشن یا "
                        "کاراکتر خاص دارد و در PowerShell/cmd به‌درستی "
                        "escape نمی‌شود.")
    g.add_argument("--find-limit", type=int, default=0,
                   help="سقف حجم جستجوی --find-name بر حسب بایت (0 = کل دیسک)")
    g.add_argument("--find-max-hits", type=int, default=50,
                   help="سقف تعداد موارد گزارش‌شده (پیش‌فرض 50)")
    g.add_argument("--dump-range", metavar="LBA:COUNT",
                   help="استخراج یک محدوده سکتور خام به فایل، مثل 9211248:64 . "
                        "رشته‌های خوانای داخلش هم چاپ می‌شود. فقط خواندن.")
    g.add_argument("--dump-out", metavar="PATH", default="dump.bin",
                   help="مسیر فایل خروجی --dump-range (پیش‌فرض dump.bin)")
    g.add_argument("--dump-strings-min", type=int, default=6,
                   help="حداقل طول رشته خوانا برای نمایش (پیش‌فرض 6)")
    g.add_argument("--dump-raw-strings", action="store_true",
                   help="نمایش همه رشته‌های خوانا بدون فیلتر نویز. پیش‌فرض فقط "
                        "رشته‌هایی که شبیه متن واقعی‌اند نشان داده می‌شوند، "
                        "چون داده فشرده دائم رشته‌های کوتاه بی‌معنا می‌سازد.")

    g = p.add_argument_group("Veeam — VBM و VBK (v1.8)")
    g.add_argument("--find-vbm", action="store_true",
                   help="جستجوی محتوای واقعی فایل .vbm (تگ XML <BackupMeta>، "
                        "نه فقط ورودی دایرکتوری). استخراج FilePath، BackupSize، "
                        "EncryptionState و غیره از روی XML مستند. فقط خواندن.")
    g.add_argument("--find-vbm-window", type=int, default=512 * KIB,
                   help="حجم پنجره خوانده‌شده بعد از هر <BackupMeta> (پیش‌فرض 512KiB)")
    g.add_argument("--find-vbm-max-hits", type=int, default=20,
                   help="سقف تعداد .vbm گزارش‌شده (پیش‌فرض 20)")
    g.add_argument("--carve-vbk", metavar="CENTER_LBA:MARGIN_GIB",
                   help="استخراج یک محدوده بزرگ و پیوسته اطراف یک LBA شناخته‌شده "
                        "به فایل، برای دادن به Veeam Extract Utility. مثل "
                        "234280000:4 یعنی 4 گیگابایت قبل و بعد از آن LBA. "
                        "چون فرمت VBK امضای عمومی مستندی ندارد (ویم آن را "
                        "منتشر نکرده)، این محدوده حدسی است نه دقیق — margin "
                        "را آن‌قدر بزرگ بگیر که مطمئن شوی شروع واقعی فایل "
                        "داخلش است. فقط خواندن.")
    g.add_argument("--carve-out", metavar="PATH", default="carved.bin",
                   help="مسیر خروجی --carve-vbk (پیش‌فرض carved.bin)")
    g.add_argument("--locate-vbk", metavar="CENTER_LBA:SIZE_BYTES",
                   help="یافتن نقطه شروع دقیق یک فایل به‌اندازه مشخص، با استفاده "
                        "از تراز بلوک (BlockAlignmentSize از .vbm) به‌جای حدس "
                        "خطی. مثل 93843712:18940297216. فقط خواندن و سریع — "
                        "فقط چند کیلوبایت در هر کاندید می‌خواند.")
    g.add_argument("--locate-align", type=int, default=65536,
                   help="تراز جستجو به بایت (پیش‌فرض 65536 = BlockAlignmentSize "
                        "معمول Veeam)")
    g.add_argument("--locate-radius-gib", type=float, default=2.0,
                   help="شعاع جستجو حول center به گیگابایت (پیش‌فرض 2)")
    g.add_argument("--locate-verify", metavar="TEXT",
                   help="علاوه بر امتیاز آنتروپی، کاندیدهای برتر را با خواندن "
                        "چند مگابایت واقعی و جستجوی این متن تایید کن. مثل "
                        "\"Active (172.17.1.253)\". وقتی چند فایل همسایه "
                        "امتیاز مشابه دارند (repository پرتراکم)، تنها راه "
                        "مطمئن است.")
    g.add_argument("--locate-verify-top-n", type=int, default=40,
                   help="چند تا از کاندیدهای برتر با محتوا تایید شود (پیش‌فرض 40)")
    g.add_argument("--locate-probe-mib", type=int, default=8,
                   help="حجم پروب محتوا برای هر کاندید به مگابایت (پیش‌فرض 8)")
    g.add_argument("--locate-verify-file", metavar="PATH",
                   help="متن جستجو را از این فایل بخوان به‌جای خط فرمان "
                        "(UTF-8، خط اول). برای وقتی که متن کوتیشن یا کاراکتر "
                        "خاص دارد و در PowerShell/cmd به‌درستی escape نمی‌شود.")
    g.add_argument("--deep-ignore-table", action="store_true",
                   help="در اسکن عمیق، محدوده پارتیشن‌های جدول را هم بگرد "
                        "(وقتی خود جدول مشکوک است)")

    g = p.add_argument_group("triage — تشخیص عمق خرابی")
    g.add_argument("--triage", action="store_true",
                   help="بررسی فارنزیک هر پارتیشنی که سالم تشخیص داده نشده: "
                        "سکتور اول، آنتروپی، جستجوی ساختار در انتها، نقشه "
                        "خرابی، و نتیجه‌گیری. فقط خواندن.")
    g.add_argument("--triage-all", action="store_true",
                   help="triage روی همه پارتیشن‌ها، حتی سالم‌ها")
    g.add_argument("--triage-samples", type=int, default=320,
                   help="تعداد نمونه نقشه خرابی (پیش‌فرض 320)")
    g.add_argument("--triage-sample-kib", type=int, default=64,
                   help="حجم هر نمونه (پیش‌فرض 64 کیلوبایت)")
    g.add_argument("--triage-tail-mib", type=int, default=512,
                   help="چقدر از انتهای پارتیشن گشته شود (پیش‌فرض 512 مگابایت)")
    g.add_argument("--triage-edge-gib", type=int, default=16,
                   help="سقف پویش ترتیبی برای یافتن اولین ساختار (گیگابایت)")
    g.add_argument("--triage-head-gib", type=int, default=8,
                   help="حجم نقشه متراکم ابتدای ولوم (پیش‌فرض 8 گیگابایت)")
    g.add_argument("--triage-head-samples", type=int, default=128,
                   help="تعداد نمونه نقشه متراکم ابتدا (پیش‌فرض 128)")
    g.add_argument("--baseline", metavar="DISK:LBA",
                   help="ولوم سالمِ کنترل به‌صورت دستی، مثل  6:32768 . در حالت "
                        "auto خودکار انتخاب می‌شود.")

    g = p.add_argument_group("ترمیم")
    g.add_argument("--plan", action="store_true", help="فقط طرح‌ها و کلاس مجوزشان")
    g.add_argument("--wizard", action="store_true", help="حالت تعاملی با بازگشت")
    g.add_argument("--action", metavar="ACTION",
                   help="اقدام: " + ", ".join(list(ACTION_BUILDERS.keys()) +
                                              list(EXTERNAL_ACTIONS)))
    g.add_argument("--part", type=int, default=None, help="شماره پارتیشن هدف")
    g.add_argument("--letter", help="حرف درایو برای chkdsk/refsutil")

    g = p.add_argument_group("ایمنی")
    g.add_argument("--apply", action="store_true", help="اجازه نوشتن")
    g.add_argument("--allow-inferred", action="store_true",
                   help="اجازه صریح برای اقدام‌های INFERRED_REBUILD")
    g.add_argument("--yes", action="store_true", help="رد شدن از تایید تایپی")
    g.add_argument("--force", action="store_true", help="deprecated; never authorizes a write or bypasses verification")
    g.add_argument("--offline", action="store_true", help="Offline کردن دیسک (ویندوز)")
    g.add_argument("--backup-dir", default="diskdoctor_backups", help="محل Journal")

    g = p.add_argument_group("Journal")
    g.add_argument("--undo", metavar="TRANSACTION_UUID", help="برگرداندن یک عملیات")
    g.add_argument("--inspect", metavar="TRANSACTION_UUID", help="نمایش وضعیت یک Journal")
    g.add_argument("--check-journals", action="store_true",
                   help="یافتن Journalهای ناتمام در backup-dir")

    g = p.add_argument_group("ایمیج")
    g.add_argument("--image-out", help="گرفتن ایمیج خام با retry و badmap")
    g.add_argument("--image-limit", type=int, default=0, help="محدود کردن حجم")
    g.add_argument("--image-retries", type=int, default=3, help="تلاش مجدد هر سکتور")
    g.add_argument("--image-fill", choices=["zero", "pat"], default="pat",
                   help="پرکننده سکتور غیرقابل‌خواندن")

    g = p.add_argument_group("خروجی و سایر")
    g.add_argument("--json", help="گزارش JSON")
    g.add_argument("--log", help="فایل لاگ")
    g.add_argument("--refs-out", help="مسیر خروجی refsutil")
    g.add_argument("--refs-work", help="مسیر working dir برای refsutil")
    g.add_argument("--refs-mode", default="QA", choices=["QS", "QA", "FS", "FA"],
                   help="حالت refsutil salvage")
    g.add_argument("--lang", choices=["fa", "en"], default="fa")
    g.add_argument("--no-color", action="store_true")
    g.add_argument("--quiet", action="store_true")
    g.add_argument("--verbose", action="store_true", help="hexdiff تغییرات")
    g.add_argument("--self-test", action="store_true", help="تست داخلی")
    g.add_argument("--help-full", action="store_true", help="راهنمای کامل")
    g.add_argument("--state-dir", default="DiskDoctor", help="persistent reports/transactions/checkpoints/logs")
    g.add_argument("--authoritative-size", type=int, help="independent authoritative source size in bytes")
    g.add_argument("--size-provenance", help="recorded source of authoritative size; OPERATOR_SUPPLIED")
    g.add_argument("--authorize-external-mutation", action="store_true", help="separate authorization for nontransactional external mutation")
    g.add_argument("--image-resume", action="store_true", help="resume validated image checkpoint")
    g.add_argument("--image-sha256", action="store_true", help="reopen and hash completed image")
    g.add_argument("--source-sha256", action="store_true", help="bind plan to full image SHA-256 in addition to samples")
    return p


def print_disk_list():
    disks = list_disks()
    if not disks:
        warn("هیچ دیسکی گزارش نشد (روی ویندوز باید Administrator باشی).")
        return EXIT_NOTFOUND
    out("")
    out(C.w(C.BOLD, " #   size          style     offline  model / letters"))
    for d in disks:
        letters = ",".join([str(v.get("Letter")) for v in d.get("volumes", [])
                            if v.get("Letter")])
        out(" %-3s %12s  %-9s %-8s %s %s" % (
            d["index"], human(d["size"]), d["style"] or "?", str(d["offline"]),
            (d["model"] or "")[:32], ("[" + letters + "]") if letters else ""))
    out("")
    info("برای اسکن:  --disk <#> --scan --explain")
    return EXIT_OK


def main(argv=None):
    global LANG, QUIET, VERBOSE, EXPLAIN, LOGFILE
    setup_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        safety.protect_outputs(sys.modules[__name__], args)
    except (core.SafetyError, DiskError, OSError) as e:
        err(str(e))
        return EXIT_BLOCKED

    if getattr(args, "baseline", None):
        try:
            dsk, lba = args.baseline.split(":")
            bpath = resolve_target(dsk)
            bd = RawDisk(bpath, writable=False)
            try:
                br = scan(bd)
                bp = [x for x in br.parts if x.start == int(lba)]
                if bp:
                    args._control = {"path": bpath, "start": bp[0].start,
                                     "sectors": bp[0].sectors,
                                     "fs": bp[0].fs_name()}
            finally:
                bd.close()
        except Exception as e:
            err("--baseline خوانده نشد: %s" % e)

    LANG = args.lang
    QUIET = args.quiet
    VERBOSE = args.verbose
    EXPLAIN = args.explain
    C.enabled = not args.no_color and sys.stdout.isatty()
    if args.log and not ((args.auto or args.all) and not args.disk):
        try:
            LOGFILE = open(args.log, "x", encoding="utf-8")
        except Exception as e:
            err("cannot open log: %s" % e)

    try:
        if args.help_full:
            parser.print_help()
            out("v2 architecture and current safety rules: docs/HARDENING.md")
            return EXIT_OK
        if args.self_test:
            return self_test()
        if args.list:
            return print_disk_list()
        if args.inspect:
            safety.inspect(sys.modules[__name__], args)
            return EXIT_OK
        if args.check_journals:
            return check_journals(safety.transaction_root(args))
        if args.undo:
            try:
                safety.undo(sys.modules[__name__], args)
                return EXIT_OK
            except Exception as e:
                err("undo failed: %s" % e)
                return EXIT_ERR
        if args.auto or args.all:
            return auto_run(args)
        if args.wizard:
            return wizard(args)
        if not args.disk:
            parser.print_help()
            out("")
            warn("هدف مشخص نشده. مثال:  --list   یا   --disk 2 --scan --explain")
            return EXIT_ARG

        try:
            path = resolve_target(args.disk)
            disk = RawDisk(path, sector_size=args.sector_size,
                           base_offset=args.offset, writable=False)
        except DiskError as e:
            err(str(e))
            low = str(e).lower()
            return EXIT_PERM if ("admin" in low or "sudo" in low) else EXIT_NOTFOUND

        try:
            if args.image_out:
                make_image(disk, args.image_out, limit=args.image_limit,
                           retries=args.image_retries, fill=args.image_fill,
                           resume=args.image_resume, final_hash=args.image_sha256)
            if args.find_vbm:
                vres = find_vbm_metadata(disk, limit=args.find_limit,
                                         window=args.find_vbm_window,
                                         max_hits=args.find_vbm_max_hits)
                print_find_vbm(vres)
                if args.json:
                    _atomic_write_json(args.json, vres)
                    ok("JSON: %s" % args.json)
                return EXIT_OK

            if args.locate_vbk:
                try:
                    lpart = args.locate_vbk.split(":")
                    llba = int(lpart[0])
                    lsize = int(lpart[1])
                except Exception:
                    err("قالب --locate-vbk باید CENTER_LBA:SIZE_BYTES باشد")
                    return EXIT_ARG
                if args.locate_verify_file:
                    try:
                        with open(args.locate_verify_file, "r",
                                 encoding="utf-8-sig") as vf:
                            args.locate_verify = vf.readline().rstrip("\r\n")
                    except Exception as e:
                        err("خواندن --locate-verify-file شکست خورد: %s" % e)
                        return EXIT_ARG
                    if not args.locate_verify:
                        err("فایل --locate-verify-file خالی است یا خط اولش خالی است")
                        return EXIT_ARG
                    info("متن جستجو از فایل خوانده شد: %r" % args.locate_verify)
                if args.locate_verify:
                    lres = locate_vbk_start_verified(
                        disk, llba, lsize, args.locate_verify,
                        align_bytes=args.locate_align,
                        radius_gib=args.locate_radius_gib,
                        verify_top_n=args.locate_verify_top_n,
                        probe_bytes=args.locate_probe_mib * MIB)
                    print_locate_vbk_verified(lres)
                else:
                    lres = locate_vbk_start(disk, llba, lsize,
                                            align_bytes=args.locate_align,
                                            radius_gib=args.locate_radius_gib)
                    print_locate_vbk(lres)
                if args.json:
                    _atomic_write_json(args.json, lres)
                    ok("JSON: %s" % args.json)
                return EXIT_OK

            if args.carve_vbk:
                try:
                    cpart = args.carve_vbk.split(":")
                    clba = int(cpart[0])
                    cmargin = float(cpart[1]) if len(cpart) > 1 else 1.0
                except Exception:
                    err("قالب --carve-vbk باید CENTER_LBA:MARGIN_GIB باشد، "
                       "مثل 234280000:4")
                    return EXIT_ARG
                cres = carve_vbk(disk, clba, cmargin, args.carve_out)
                print_dump_range(cres)
                if args.json:
                    _atomic_write_json(args.json, cres)
                    ok("JSON: %s" % args.json)
                return EXIT_OK

            if args.dump_range:
                try:
                    part = args.dump_range.split(":")
                    slba = int(part[0])
                    cnt = int(part[1]) if len(part) > 1 else 1
                except Exception:
                    err("قالب --dump-range باید LBA:COUNT باشد، مثل 9211248:64")
                    return EXIT_ARG
                dres = dump_range(disk, slba, cnt, args.dump_out,
                                  args.dump_strings_min,
                                  filter_noise=not args.dump_raw_strings)
                print_dump_range(dres)
                if args.json:
                    _atomic_write_json(args.json, dres)
                    ok("JSON: %s" % args.json)
                return EXIT_OK

            if args.find_name_file:
                try:
                    with open(args.find_name_file, "r", encoding="utf-8-sig") as nf:
                        args.find_name = nf.readline().rstrip("\r\n")
                except Exception as e:
                    err("خواندن --find-name-file شکست خورد: %s" % e)
                    return EXIT_ARG
                if not args.find_name:
                    err("فایل --find-name-file خالی است یا خط اولش خالی است")
                    return EXIT_ARG
                info("متن جستجو از فایل خوانده شد: %r" % args.find_name)
            if args.find_name:
                fres = find_name(disk, args.find_name, limit=args.find_limit,
                                 max_hits=args.find_max_hits)
                print_find_name(fres, disk)
                if args.json:
                    _atomic_write_json(args.json, fres)
                    ok("JSON: %s" % args.json)
                return EXIT_OK

            r = scan(disk, deep=args.deep, deep_step=args.deep_step,
                     deep_limit=args.deep_limit, time_budget=args.time_budget,
                     ignore_table=args.deep_ignore_table)
            print_report(r)
            tri = None
            if args.triage or args.triage_all:
                tri = run_triage(disk, r, args)
            if args.json:
                doc = r.to_dict()
                if tri is not None:
                    doc["triage"] = tri
                _atomic_write_json(args.json, doc)
                ok("JSON report: %s" % args.json)
            safety.persist_report(sys.modules[__name__], disk, r, args, triage=tri)
            print_plans(disk, r, suggest_plans(disk, r))
            if args.action:
                rc = execute_action(disk, r, args, args.action)
                safety.persist_report(sys.modules[__name__], disk, r, args, triage=tri, final=True)
                return rc
            info(T("readonly_note"))
            return EXIT_OK
        finally:
            disk.close()
    finally:
        if LOGFILE:
            LOGFILE.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("")
        sys.exit(EXIT_CANCEL)
    except (core.SafetyError, DiskError, OSError, ValueError) as e:
        err(str(e))
        sys.exit(EXIT_ERR)
