#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
================================================================================
DiskDoctor v1.5  —  Forensic scanner + evidence-based repair engine
اسکن فارنزیک و ترمیم مبتنی بر شواهد برای دیسک‌هایی که پس از اصلاح VMDK
در ویندوز Attach/Assign شده‌اند.
================================================================================

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
  --force                عبور از محافظت‌ها. blockerهای سراسری را هم رد
                         می‌کند؛ فقط وقتی دقیقاً می‌دانی چه می‌کنی.
  --offline              پاک کردن فلگ ReadOnly، Offline کردن دیسک هنگام
                         نوشتن و Online کردن دوباره (ویندوز).
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

VERSION = "1.5"
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
        "sys_disk_block": "این دیسک شامل ولوم سیستمی است. نوشتن مسدود شد. عبور: --force.",
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
        "sys_disk_block": "This disk holds a system volume. Writing blocked. Override: --force.",
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
        self._open()

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
        """Aligned-safe write via read-modify-write of the touched sectors."""
        if not self.writable:
            raise DiskError("disk opened read-only")
        if not data:
            return 0
        s = self.sector
        abs_off = self.base + offset
        start = (abs_off // s) * s
        end = ((abs_off + len(data) + s - 1) // s) * s
        self.fh.seek(start)
        block = bytearray(self.fh.read(end - start))
        if len(block) < end - start:
            block += bytes((end - start) - len(block))
        skip = abs_off - start
        block[skip:skip + len(data)] = data
        self.fh.seek(start)
        n = self.fh.write(bytes(block))
        try:
            self.fh.flush()
            os.fsync(self.fh.fileno())
        except Exception:
            pass
        return n

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
        self.signals[name] = {"value": bool(value), "why": why}

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
            "signals": {k: v for k, v in self.signals.items()},
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
            "generated": datetime.datetime.now().isoformat(timespec="seconds"),
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
    r.carved = dedup_parts(r.carved, [] if ignore_table else r.parts)

    # ---- evidence ---------------------------------------------------------
    for p in r.all_parts:
        p.ev = build_evidence(disk, p)
    mark_overlaps(r.all_parts)

    collect_disk_blockers(disk, r)
    collect_warnings(disk, r)
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
                "sha_old": hashlib.sha256(self.old or b"").hexdigest()[:16],
                "sha_new": hashlib.sha256(self.new).hexdigest()[:16]}


def _atomic_write_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    if not IS_WIN:
        try:
            dfd = os.open(os.path.dirname(path) or ".", os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except Exception:
            pass


class PatchTransaction(object):
    """Journal-first write transaction with per-patch status."""

    def __init__(self, disk, action_key, patches, backup_dir, meta=None):
        self.disk = disk
        self.action = action_key
        self.patches = patches
        self.backup_dir = backup_dir
        self.meta = meta or {}
        self.path = None
        self.state = "new"

    def _doc(self):
        return {
            "tool": "DiskDoctor", "version": VERSION,
            "time": datetime.datetime.now().isoformat(timespec="seconds"),
            "target": self.disk.path, "sector_size": self.disk.sector,
            "disk_size": self.disk.size, "action": self.action,
            "state": self.state, "meta": self.meta,
            "patches": [p.to_dict(i) for i, p in enumerate(self.patches)],
        }

    def _persist(self):
        _atomic_write_json(self.path, self._doc())

    def begin(self):
        """Capture the old bytes and commit the journal to stable storage."""
        os.makedirs(self.backup_dir, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.path = os.path.join(self.backup_dir, "journal_%s_%s.json" % (ts, self.action))
        for p in self.patches:
            p.load_old(self.disk)
            p.status = "pending"
        self.state = "open"
        self._persist()
        return self.path

    def run(self, force=False):
        """Apply every patch, verifying and recording each one as it lands."""
        if self.state != "open":
            raise DiskError("transaction was not opened")
        written = 0
        try:
            for p in self.patches:
                cur = self.disk.read_at(p.offset, len(p.new))
                if cur == p.new:
                    p.status = "skipped"
                    self._persist()
                    continue
                if p.old is not None and cur != p.old and not force:
                    p.status = "failed"
                    self.state = "partial"
                    self._persist()
                    raise DiskError("محتوای دیسک از زمان پیش‌نمایش عوض شده "
                                    "(آفست 0x%X). با --force عبور کن." % p.offset)
                self.disk.write_at(p.offset, p.new)
                back = self.disk.read_at(p.offset, len(p.new))
                if back != p.new and not force:
                    p.status = "failed"
                    self.state = "partial"
                    self._persist()
                    raise DiskError("verify شکست خورد در 0x%X — نوشتن اثر نکرد. "
                                    "در ویندوز احتمالاً ولوم mount است؛ با "
                                    "--offline دوباره اجرا کن." % p.offset)
                p.status = "done"
                written += len(p.new)
                self._persist()
            self.state = "complete"
            self._persist()
            return written
        except Exception:
            if self.state == "open":
                self.state = "partial"
                self._persist()
            raise


def load_journal(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def inspect_journal(path):
    j = load_journal(path)
    out("")
    out(C.w(C.BOLD, " Journal: %s" % path))
    out("   action  : %s" % j.get("action"))
    out("   target  : %s" % j.get("target"))
    out("   time    : %s" % j.get("time"))
    st = j.get("state")
    col = C.GREEN if st == "complete" else (C.YELLOW if st in ("partial", "open") else C.GREY)
    out("   state   : %s" % C.w(col, str(st)))
    out("")
    out(C.w(C.DIM, "   #  status    offset            len  label"))
    for p in j.get("patches", []):
        c = {"done": C.GREEN, "pending": C.YELLOW, "failed": C.RED,
             "skipped": C.GREY, "reverted": C.CYAN}.get(p.get("status"), C.GREY)
        out("   %-2d %s  0x%012X %6d  %s" %
            (p.get("i", 0), C.w(c, "%-8s" % p.get("status")), p["offset"],
             p["len"], p["label"]))
    out("")
    if st in ("open", "partial"):
        warn("این Journal ناتمام است. با --undo می‌توانی همان بخشی که واقعاً "
             "نوشته شده را برگردانی.")
    return j


def undo_journal(path, force=False):
    """Reverse a journal, including a partial one left behind by a crash."""
    j = load_journal(path)
    target = j["target"]
    info("undo target: %s (action=%s, state=%s)" %
         (target, j.get("action"), j.get("state")))
    restored = 0
    with RawDisk(target, sector_size=j.get("sector_size"), writable=True) as d:
        for pd in reversed(j.get("patches", [])):
            old = base64.b64decode(pd["old_b64"])
            new = base64.b64decode(pd["new_b64"])
            cur = d.read_at(pd["offset"], len(new))
            status = pd.get("status")
            if cur == old:
                pd["status"] = "reverted"
                continue
            if cur != new and not force:
                warn("رد شد: %s @0x%X — محتوای فعلی نه old است نه new."
                     % (pd["label"], pd["offset"]))
                continue
            # a 'pending' patch whose content equals new was written just before
            # the crash; treat it as done and revert it too
            d.write_at(pd["offset"], old)
            back = d.read_at(pd["offset"], len(old))
            pd["status"] = "reverted" if back == old else "revert_failed"
            if back == old:
                restored += len(old)
            else:
                err("بازگردانی %s @0x%X تایید نشد." % (pd["label"], pd["offset"]))
            dbg("reverted %s (was %s)" % (pd["label"], status))
    j["state"] = "rolled_back"
    j["undo_time"] = datetime.datetime.now().isoformat(timespec="seconds")
    _atomic_write_json(path, j)
    ok("%s — %d bytes restored" % (T("undo_done"), restored))
    return restored


def check_journals(backup_dir):
    """Warn about journals that were never completed (crash detection)."""
    if not os.path.isdir(backup_dir):
        info("پوشه بکاپ وجود ندارد: %s" % backup_dir)
        return EXIT_OK
    bad = []
    for fn in sorted(os.listdir(backup_dir)):
        if not (fn.startswith("journal_") and fn.endswith(".json")):
            continue
        p = os.path.join(backup_dir, fn)
        try:
            j = load_journal(p)
        except Exception:
            bad.append((p, "unreadable"))
            continue
        if j.get("state") in ("open", "partial"):
            done = sum(1 for x in j.get("patches", []) if x.get("status") == "done")
            bad.append((p, "%s — %d/%d patches written" %
                        (j.get("state"), done, len(j.get("patches", [])))))
    if not bad:
        ok("هیچ Journal ناتمامی پیدا نشد.")
        return EXIT_OK
    warn("Journalهای ناتمام:")
    for p, why in bad:
        out("   %s  (%s)" % (p, why))
    info("برای بررسی: --inspect <path>   برای برگشت: --undo <path>")
    return EXIT_OK


def dump_structures(disk, backup_dir, tag="pre"):
    """Save the first and last 34 sectors before any structural change."""
    os.makedirs(backup_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.join(backup_dir, "struct_%s_%s" % (tag, ts))
    head = disk.read_at(0, 34 * disk.sector)
    tail_off = max(0, disk.size - 34 * disk.sector)
    tail = disk.read_at(tail_off, 34 * disk.sector)
    for suffix, data in (("_head.bin", head), ("_tail.bin", tail)):
        with open(base + suffix, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
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
        self.title = title
        self.patches = patches
        self.gate = gate
        self.note = note
        self.post = list(post)
        self.notes = list(notes)


# --- GPT: byte-for-byte restores ---------------------------------------------

def act_gpt_restore_primary(disk, r, args):
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
            bootable=(i == 0))
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
    parts = _rebuild_preconditions(disk, r, "gpt-rebuild")
    unknown = [p for p in parts if p.fs_name() not in FS_TO_GPT_GUID]
    if unknown:
        raise Blocked("gpt-rebuild",
                      ["فایل‌سیستم پارتیشن #%d (%s) شناخته‌شده نیست؛ Type GUID "
                       "حدس زده نمی‌شود" % (p.num, p.fs_name()) for p in unknown])
    entries = []
    for i, p in enumerate(parts):
        g = FS_TO_GPT_GUID[p.fs_name()]
        if p.fs_name() in ("FAT32", "FAT16") and i == 0 and \
                p.sectors * disk.sector <= 2 * GIB and \
                p.start <= (8 * MIB) // disk.sector:
            g = GUID_ESP
        entries.append({"first": p.start, "last": p.end, "type_guid": g,
                        "part_guid": p.guid or None,
                        "name": p.name or (p.fs_name() + " volume"), "attrs": 0})
    dg = None
    for src in (r.gpt_p, r.gpt_b):
        if src and src.get("header") and src["header"].get("disk_guid") not in (
                None, "", "00000000-0000-0000-0000-000000000000"):
            dg = src["header"]["disk_guid"]
            break
    notes = ["#%d %s LBA %d..%d — extent proof: %s"
             % (p.num, p.fs_name(), p.start, p.end, p.ev.extent_source) for p in parts]
    if dg is None:
        notes.append("Disk GUID قابل استخراج نبود؛ یک GUID جدید تولید می‌شود. "
                     "این آخرین چاره است، نه رفتار عادی.")
    for p in parts:
        if not p.guid:
            notes.append("#%d: GUID یکتای پارتیشن قابل بازیابی نبود؛ جدید تولید "
                         "می‌شود (روی داده اثر ندارد، ولی شناسه قبلی از دست می‌رود)."
                         % p.num)
    built = build_gpt(disk.sectors, disk.sector, entries, disk_guid=dg)
    patches = [Patch(0, build_protective_mbr(disk.sectors), "protective MBR (LBA 0)"),
               Patch(built["primary_entries_lba"] * disk.sector, built["primary_entries"],
                     "GPT primary entry array"),
               Patch(built["primary_header_lba"] * disk.sector, built["primary_header"],
                     "GPT primary header"),
               Patch(built["backup_entries_lba"] * disk.sector, built["backup_entries"],
                     "GPT backup entry array"),
               Patch(built["backup_header_lba"] * disk.sector, built["backup_header"],
                     "GPT backup header")]
    desc = ", ".join("%s@%d" % (p.fs_name(), p.start) for p in parts)
    return RepairAction(
        "gpt-rebuild", "ساخت کامل GPT از %d کاندید strong: %s" % (len(parts), desc),
        patches, GATE_INFERRED,
        note="Protective MBR + GPT اصلی + GPT پشتیبان نوشته می‌شود.",
        post=["rescan"], notes=notes)


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
    if r.scheme.startswith("MBR"):
        old = disk.read_lba(0, 1)
        if len(old) < 512:
            raise Blocked("parttype-fix", "سکتور 0 خوانده نشد")
        sec = bytearray(old)
        changed = []
        for p in r.parts:
            if p.slot is None or p.source != "MBR" or not p.fs:
                continue
            if p.ev and p.ev.level in ("weak", "blocked"):
                continue
            want = FS_TO_MBR_TYPE.get(p.fs_name())
            if want is None:
                continue
            off = 0x1BE + p.slot * 16 + 4
            if sec[off] != want:
                changed.append("slot %d: 0x%02X -> 0x%02X (%s)"
                               % (p.slot, sec[off], want, p.fs_name()))
                sec[off] = want
        if not changed:
            raise Blocked("parttype-fix",
                          "همه نوع‌های پارتیشن با فایل‌سیستم واقعی می‌خوانند "
                          "(یا شواهد کافی برای تغییر نیست)")
        return RepairAction("parttype-fix", "اصلاح نوع پارتیشن MBR: " + "; ".join(changed),
                            [Patch(0, bytes(sec), "MBR type bytes (LBA 0)")],
                            GATE_SAFE, post=["rescan"])

    src = r.gpt_p if (r.gpt_p and r.gpt_p["entries"]) else r.gpt_b
    if not (src and src["entries"] and src["valid"]):
        raise Blocked("parttype-fix", "جدول GPT معتبری برای اصلاح نیست")
    esz = src["header"]["entry_size"]
    elba = src["header"]["entry_lba"]
    arr = bytearray(src["entry_bytes"])
    changed = []
    for p in r.parts:
        if not p.fs or p.slot is None:
            continue
        if p.ev and p.ev.level in ("weak", "blocked"):
            continue
        want = FS_TO_GPT_GUID.get(p.fs_name())
        if not want:
            continue
        off = p.slot * esz
        cur = guid_to_str(bytes(arr[off:off + 16]))
        if cur.upper() != want:
            arr[off:off + 16] = str_to_guid(want)
            changed.append("#%d: %s -> %s" % (p.num, cur, want))
    if not changed:
        raise Blocked("parttype-fix", "همه Type GUIDها درست‌اند")
    # only the entry array bytes change; the header keeps everything but its CRCs
    new_hdr = gpt_recrc_header(src["header_sector"], disk.sector, bytes(arr))
    patches = [Patch(elba * disk.sector, bytes(arr), "GPT entry array (type GUIDs only)"),
               Patch(src["header_lba"] * disk.sector, new_hdr,
                     "GPT header CRC fields")]
    return RepairAction("parttype-fix", "اصلاح Type GUID: " + "; ".join(changed),
                        patches, GATE_SAFE,
                        note="فقط 16 بایت Type GUID هر ورودی و CRCهای هدر عوض می‌شود.",
                        post=["rescan"])


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
    """What would the gate say about this action right now?"""
    if action in EXTERNAL_ACTIONS:
        return GATE_SAFE
    builder = ACTION_BUILDERS.get(action)
    if not builder:
        return GATE_BLOCKED
    fake = argparse.Namespace(part=part)
    try:
        act = builder(disk, r, fake)
    except Blocked:
        return GATE_BLOCKED
    except Exception:
        return GATE_BLOCKED
    exempt = BLOCKER_EXEMPT.get(action, ())
    for k, _ in r.blockers:
        if k not in exempt:
            return GATE_BLOCKED
    return act.gate


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


def make_image(disk, path, limit=0, chunk=8 * MIB, retries=3, fill="zero"):
    """Raw image with retries and an explicit bad-sector map."""
    total = disk.size if not limit else min(disk.size, limit)
    sec = disk.sector
    bad_ranges = []
    done = 0
    bad_bytes = 0
    t0 = time.time()
    with open(path, "wb") as f:
        while done < total:
            n = min(chunk, total - done)
            data = _read_retry(disk, done, n, retries)
            if data is not None and len(data) == n:
                f.write(data)
                done += n
                _img_progress(done, total, bad_bytes)
                continue
            # descend to sector level inside the failing chunk
            for off in range(done, done + n, sec):
                m = min(sec, total - off)
                d = _read_retry(disk, off, m, retries)
                if d is not None and len(d) == m:
                    f.write(d)
                else:
                    f.write(_fill_block(fill, m))
                    bad_bytes += m
                    if bad_ranges and bad_ranges[-1]["end"] == off:
                        bad_ranges[-1]["end"] = off + m
                        bad_ranges[-1]["sectors"] += 1
                    else:
                        bad_ranges.append({"start": off, "end": off + m,
                                           "start_lba": off // sec, "sectors": 1})
            done += n
            _img_progress(done, total, bad_bytes)
    if not QUIET:
        sys.stdout.write("\r" + " " * 72 + "\r")
    badmap = {
        "tool": "DiskDoctor", "version": VERSION,
        "time": datetime.datetime.now().isoformat(timespec="seconds"),
        "source": disk.path, "image": path, "sector_size": sec,
        "imaged_bytes": done, "unreadable_bytes": bad_bytes,
        "fill_pattern": fill, "retries_per_sector": retries,
        "bad_ranges": bad_ranges,
    }
    _atomic_write_json(path + ".badmap.json", badmap)
    if bad_bytes:
        warn("%s غیرقابل خواندن بود در %d محدوده — با الگوی '%s' پر شد و در "
             "%s.badmap.json ثبت شد." % (human(bad_bytes), len(bad_ranges), fill, path))
        for br in bad_ranges[:5]:
            out("     bad: LBA %d .. %d (%d sectors)"
                % (br["start_lba"], br["start_lba"] + br["sectors"] - 1, br["sectors"]))
        if len(bad_ranges) > 5:
            out("     ... %d more ranges" % (len(bad_ranges) - 5))
    ok("image written: %s (%s in %.1fs)" % (path, human(done), time.time() - t0))
    return path, badmap


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
        f = os.path.join(tempfile.gettempdir(), "dd_diskpart.txt")
        with open(f, "w") as fh:
            fh.write(script)
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
        f = os.path.join(tempfile.gettempdir(), "dd_rescan.txt")
        with open(f, "w") as fh:
            fh.write("rescan\r\nexit\r\n")
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
    if not IS_WIN:
        warn("chkdsk فقط روی ویندوز معنا دارد.")
        return 1
    args = ["chkdsk", "%s:" % letter.rstrip(":")]
    if fix:
        args.append("/f")
    info("running: %s" % " ".join(args))
    rc, so, se = run_cmd(args, timeout=3600)
    out(so[-4000:])
    if se.strip():
        warn(se[-1000:])
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
    for d in (work_dir, target_dir):
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
    problems = []
    idx = win_disk_index_from_path(disk.path)
    if IS_WIN and idx is not None and idx in system_disk_indices():
        problems.append(T("sys_disk_block"))
    if IS_LINUX and disk.is_device:
        for s in system_disk_indices():
            if isinstance(s, str) and disk.path.startswith(s):
                problems.append(T("sys_disk_block"))
    if not is_admin() and disk.is_device:
        problems.append(T("need_admin"))
    if problems and not args.force:
        for p in problems:
            err(p)
        return False
    for p in problems:
        warn("FORCED: " + p)
    return True


def print_blocked(action, reasons):
    out("")
    out(C.w(C.BOLD + C.RED, " REPAIR BLOCKED: %s" % action))
    for rr in reasons:
        out("   " + C.w(C.RED, "• ") + rr)
    out("")
    info("هیچ بایتی نوشته نشد. برای دیدن جزئیات شواهد: --explain")


def execute_action(disk, r, args, action_key):
    if action_key in EXTERNAL_ACTIONS:
        return run_external(disk, r, args, action_key)
    builder = ACTION_BUILDERS.get(action_key)
    if not builder:
        err("unknown action: %s" % action_key)
        return EXIT_ARG

    # --- build (the builder itself refuses when evidence is insufficient) ---
    try:
        act = builder(disk, r, args)
    except Blocked as b:
        print_blocked(b.action, b.reasons)
        return EXIT_BLOCKED
    except DiskError as e:
        err("cannot build action %s: %s" % (action_key, e))
        return EXIT_ERR

    # --- disk-level blockers ------------------------------------------------
    exempt = BLOCKER_EXEMPT.get(action_key, ())
    active = [(k, w) for k, w in r.blockers if k not in exempt]
    if active and not args.force:
        print_blocked(action_key, ["[%s] %s" % (k, w) for k, w in active] +
                      ["blockerهای سراسری دیسک اجازه هیچ نوشتنی نمی‌دهند "
                       "(عبور فقط با --force و با پذیرش کامل ریسک)"])
        return EXIT_BLOCKED
    for k, w in active:
        warn("FORCED past disk blocker [%s]: %s" % (k, w))

    out("")
    out(C.w(C.BOLD, " ACTION: %s   %s" % (
        act.key, C.w(GATE_LABEL.get(act.gate, C.GREY), "[%s]" % act.gate))))
    out("   %s" % act.title)
    if act.note:
        out("   note : %s" % act.note)
    for n in act.notes:
        out("   %s %s" % (C.w(C.GREY, "-"), n))

    total = preview_patches(disk, act.patches)
    if total == 0:
        info("هیچ تغییری لازم نیست؛ محتوای فعلی همان چیزی است که باید باشد.")
        return EXIT_OK
    if not args.apply:
        warn(T("no_write_wo_apply"))
        if act.gate == GATE_INFERRED:
            info("این اقدام ساختار را سنتز می‌کند؛ برای اجرا هم --apply لازم است "
                 "هم --allow-inferred.")
        return EXIT_OK

    # --- gate enforcement ---------------------------------------------------
    if act.gate == GATE_INFERRED and not args.allow_inferred and not args.force:
        print_blocked(action_key, [T("need_inferred")])
        return EXIT_BLOCKED
    if not privilege_gate(disk, args):
        return EXIT_PERM

    warn("قبل از نوشتن: ایمیج داری؟ اگر نه، Ctrl+C بزن و اول --image-out بگیر.")
    if not confirm(assume_yes=args.yes):
        out(T("cancelled"))
        return EXIT_CANCEL

    base = dump_structures(disk, args.backup_dir, "pre")
    info("ساختارهای فعلی ذخیره شد: %s_{head,tail}.bin" % base)

    idx = win_disk_index_from_path(disk.path)
    went_offline = False
    vol_handles = []
    if IS_WIN and idx is not None:
        if args.offline:
            info("taking disk %d offline ..." % idx)
            win_set_readonly(idx, False)
            went_offline = win_set_offline(idx, True)
            if not went_offline:
                warn("offline نشد؛ نوشتن ممکن است رد شود.")
        elif act.key.startswith("vbr-restore"):
            for v in _win_disk_volumes(idx):
                if v.get("Letter"):
                    h = win_lock_dismount(str(v["Letter"]))
                    if h:
                        vol_handles.append(h)
                        info("volume %s: locked + dismounted" % v["Letter"])
                    else:
                        warn("قفل کردن ولوم %s ناموفق بود؛ با --offline دوباره "
                             "اجرا کن." % v["Letter"])

    tx = PatchTransaction(disk, act.key, act.patches, args.backup_dir,
                          meta={"title": act.title, "gate": act.gate,
                                "struct_backup": base, "notes": act.notes})
    rc = EXIT_OK
    try:
        jp = tx.begin()          # journal on stable storage BEFORE any write
        ok("%s (pre-write): %s" % (T("journal_saved"), jp))
        disk.reopen(writable=True)
        written = tx.run(force=args.force)
        ok("%s: %s (%d bytes)" % (T("applied"), act.key, written))
        info("برگرداندن: python %s --undo \"%s\"" %
             (os.path.basename(sys.argv[0]), jp))
    except DiskError as e:
        err(str(e))
        err("Journal با وضعیت '%s' ذخیره شد: %s" % (tx.state, tx.path))
        err("برای برگرداندن همان بخشی که نوشته شد: --undo \"%s\"" % tx.path)
        rc = EXIT_ERR
    finally:
        for h in vol_handles:
            win_close_handle(h)
        if went_offline:
            info("bringing disk %d back online ..." % idx)
            try:
                win_set_offline(idx, False)
            except Exception as e:
                warn("online کردن ناموفق بود: %s — دستی Online کن." % e)
        try:
            disk.reopen(writable=False)
        except DiskError as e:
            warn("بازکردن مجدد فقط-خواندن ناموفق بود: %s" % e)

    if rc == EXIT_OK:
        for step in act.post:
            if step == "rescan" and IS_WIN:
                win_rescan()
                ok("Windows rescan issued.")
            elif step == "chkdsk":
                info("گام بعدی پیشنهادی: chkdsk X: /f پس از اینکه ویندوز حرف "
                     "درایو داد.")
        info("اسکن مجدد برای تایید نتیجه ...")
        print_report(scan(disk))
    return rc


def run_external(disk, r, args, key):
    idx = win_disk_index_from_path(disk.path)
    if key == "rescan":
        return EXIT_OK if win_rescan() else EXIT_ERR
    letter = args.letter
    if not letter and IS_WIN and idx is not None:
        letters = [v.get("Letter") for v in _win_disk_volumes(idx) if v.get("Letter")]
        if len(letters) == 1:
            letter = letters[0]
        elif letters:
            info("حرف درایوهای این دیسک: %s — با --letter انتخاب کن." % ", ".join(letters))
            return EXIT_ARG
    if not letter:
        err("این اقدام به حرف درایو نیاز دارد: --letter E")
        return EXIT_ARG
    if key == "chkdsk":
        if not args.apply:
            warn("chkdsk /f روی ولوم می‌نویسد. با --apply اجرا کن.")
            return EXIT_OK
        return EXIT_OK if run_chkdsk(letter, fix=True) == 0 else EXIT_ERR
    if key == "refsutil":
        work = args.refs_work or os.path.join(args.backup_dir, "refs_work")
        tgt = args.refs_out or os.path.join(args.backup_dir, "refs_salvage")
        mode = "-" + (args.refs_mode or "QA").upper().lstrip("-")
        return EXIT_OK if run_refsutil(letter, work, tgt, mode) == 0 else EXIT_ERR
    return EXIT_ARG


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
        baseline=None)
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
    global QUIET, EXPLAIN
    prev_q, prev_e = QUIET, EXPLAIN
    QUIET, EXPLAIN = True, False
    tmp = tempfile.mkdtemp(prefix="diskdoctor11_")
    results = []

    def check(name, cond, extra=""):
        results.append((name, bool(cond)))
        tag = "\033[32mPASS\033[0m" if cond else "\033[31mFAIL\033[0m"
        print("  [%s] %s%s" % (tag, name, ("  -- %s" % (extra,)) if extra and not cond else ""))
        return bool(cond)

    print("DiskDoctor %s self-test" % VERSION)
    print("workdir: %s\n" % tmp)

    # ================================================================== T1 ==
    # FAT32: the parser must read BPB_BkBootSec from 0x32, not 0x34
    p = os.path.join(tmp, "fat32_bk17.img")
    img = _Img(p, 64 * MIB)
    _put_fat32(img, 2048, 40960)
    m = bytearray(512)
    m[0x1BE:0x1CE] = build_mbr_entry(0x0C, 2048, 40960, True)
    m[510:512] = b"\x55\xAA"
    img.put(0, bytes(m))
    fs = probe_fs(img.read(2048, 8), 512)
    check("T1 FAT32 detected", fs and fs["fs"] == "FAT32", fs)
    check("T1 BkBootSec read from 0x32 (=17, not the 6 decoy at 0x34)",
          fs["fields"]["bk_boot_sec"] == TEST_FAT32_BKBOOT,
          fs["fields"].get("bk_boot_sec"))
    check("T1 FSInfo read from 0x30 (=1)", fs["fields"]["fs_info"] == TEST_FAT32_FSINFO,
          fs["fields"].get("fs_info"))
    d, r = _scan_file(p)
    ev = r.parts[0].ev
    check("T1 mirror found at start+17", ev.signals["mirror_signature"]["value"],
          ev.signals["mirror_signature"]["why"])
    check("T1 mirror BPB matches", ev.signals["mirror_bpb_match"]["value"])
    check("T1 hidden_sectors signal passes", ev.signals["hidden_sectors"]["value"])
    check("T1 evidence level strong", r.parts[0].level == "strong",
          (r.parts[0].level, ev.confidence, ev.extent_source))
    d.close()

    # ================================================================== T2 ==
    # exFAT VBR checksum is really verified, and a single flipped byte fails it
    p2 = os.path.join(tmp, "exfat.img")
    img2 = _Img(p2, 64 * MIB)
    _put_exfat(img2, 2048, 40960)
    m = bytearray(512)
    m[0x1BE:0x1CE] = build_mbr_entry(0x07, 2048, 40960, True)
    m[510:512] = b"\x55\xAA"
    img2.put(0, bytes(m))
    d, r = _scan_file(p2)
    ev = r.parts[0].ev
    check("T2 exFAT checksum verified", ev.signals["exfat_checksum"]["value"],
          ev.signals["exfat_checksum"]["why"])
    check("T2 PartitionOffset matches start", ev.signals["partition_offset"]["value"])
    check("T2 extent proven by checksum+offset",
          ev.extent_source and "checksum" in ev.extent_source, ev.extent_source)
    check("T2 exFAT level strong", r.parts[0].level == "strong", r.parts[0].level)
    d.close()
    sec5 = bytearray(img2.read(2048 + 5, 1))
    sec5[100] ^= 0xFF                       # flip a byte the checksum covers
    img2.put(2048 + 5, bytes(sec5))
    d, r = _scan_file(p2)
    ev = r.parts[0].ev
    check("T2b corrupted VBR fails the checksum",
          ev.signals["exfat_checksum"]["value"] is False)
    check("T2b extent no longer proven by checksum",
          not (ev.extent_source or "").startswith("exFAT"), ev.extent_source)
    d.close()

    # ================================================================== T3 ==
    # NTFS mirror position: right distance = proof, wrong distance = no proof
    p3 = os.path.join(tmp, "ntfs_ok.img")
    img3 = _Img(p3, 64 * MIB)
    _put_ntfs(img3, 2048, 40960)
    m = bytearray(512)
    m[0x1BE:0x1CE] = build_mbr_entry(0x07, 2048, 40960, True)
    m[510:512] = b"\x55\xAA"
    img3.put(0, bytes(m))
    d, r = _scan_file(p3)
    ev = r.parts[0].ev
    check("T3 NTFS mirror position proves the extent",
          ev.signals["mirror_position"]["value"] and
          "backup boot sector" in (ev.extent_source or ""), ev.extent_source)
    check("T3 NTFS level strong", r.parts[0].level == "strong", r.parts[0].level)
    d.close()

    p3b = os.path.join(tmp, "ntfs_wrong_span.img")
    img3b = _Img(p3b, 64 * MIB)
    vbr = _mk_ntfs_vbr(40960, hidden=2048)
    img3b.put(2048, vbr)
    img3b.put(2048 + 30000, vbr)            # mirror at the WRONG distance
    m = bytearray(512)
    m[0x1BE:0x1CE] = build_mbr_entry(0x07, 2048, 30001, True)
    m[510:512] = b"\x55\xAA"
    img3b.put(0, bytes(m))
    d, r = _scan_file(p3b)
    ev = r.parts[0].ev
    check("T3b mirror at the wrong distance is not accepted",
          ev.signals["mirror_position"]["value"] is False,
          ev.signals["mirror_position"]["why"])
    check("T3b extent conflict is a blocker",
          any(k == "extent_conflict" for k, _ in ev.blockers),
          [k for k, _ in ev.blockers])
    d.close()

    # ================================================================== T4 ==
    # A lone mirror must not become a ghost partition
    p4 = os.path.join(tmp, "lone_mirror.img")
    img4 = _Img(p4, 64 * MIB)
    _put_ntfs(img4, 2048, 40960)
    img4.zero(2048)                         # destroy the primary VBR only
    img4.zero(0, 1)                         # and the partition table
    d, r = _scan_file(p4, deep=True)
    ghosts = [c for c in r.carved if c.start == 2048 + 40960 - 1]
    check("T4 the surviving mirror is seen", len(ghosts) == 1,
          [c.start for c in r.carved])
    if ghosts:
        check("T4 it is flagged as a mirror copy, not a volume start",
              any(k == "is_mirror_copy" for k, _ in ghosts[0].ev.blockers),
              [k for k, _ in ghosts[0].ev.blockers])
        check("T4 it can never enter a rebuild",
              ghosts[0] not in strong_candidates(r))
    d.close()

    # ================================================================= T4b ==
    # Ghost-partition regression: a lone mirror next to a healthy volume must
    # not turn into a second partition in a rebuild.
    p4b = os.path.join(tmp, "ghost.img")
    img4b = _Img(p4b, 128 * MIB)
    _put_ntfs(img4b, 2048, 40960)            # healthy volume
    _put_exfat(img4b, 65536, 40960)          # second healthy volume
    img4b.zero(65536)                        # kill only the exFAT primary VBR
    img4b.zero(0, 1)
    d, r = _scan_file(p4b, deep=True)
    ghost = [c for c in r.carved if c.start == 65536 + 12]
    check("T4b the orphan exFAT mirror is visible", len(ghost) == 1,
          [c.start for c in r.carved])
    if ghost:
        check("T4b it is identified as a mirror by its PartitionOffset",
              any(k == "is_mirror_copy" for k, _ in ghost[0].ev.blockers),
              [k for k, _ in ghost[0].ev.blockers])
    strong4b = strong_candidates(r)
    check("T4b only the healthy NTFS volume is strong",
          [c.start for c in strong4b] == [2048], [c.start for c in strong4b])
    d.close()
    act, reasons = _build(p4b, "mbr-rebuild")
    check("T4b rebuild refuses while an unproven candidate is present",
          act is None, "built anyway")

    # ================================================================== T5 ==
    # GPT byte-for-byte restore keeps non-standard metadata intact
    p5 = os.path.join(tmp, "gpt_es256.img")
    img5 = _Img(p5, 256 * MIB)
    tot5 = (256 * MIB) // 512
    _put_ntfs(img5, 2048, 204800)
    _put_fat32(img5, 262144, 100000)
    ents = [{"first": 2048, "last": 2048 + 204800 - 1, "type_guid": GUID_MSDATA,
             "name": "data one"},
            {"first": 262144, "last": 262144 + 100000 - 1, "type_guid": GUID_MSDATA,
             "name": "data two"}]
    b5 = build_gpt(tot5, 512, ents, disk_guid="AABBCCDD-1122-3344-5566-778899AABBCC")
    # make the primary header non-standard on purpose: entry_size 256 and a
    # non-zero reserved dword, so a regenerating "fix" would be detectable
    hdr = bytearray(b5["primary_header"])
    struct.pack_into("<I", hdr, 20, 0xDEADBEEF)     # reserved field
    struct.pack_into("<I", hdr, 16, 0)
    struct.pack_into("<I", hdr, 16, crc32(bytes(hdr[:92])))
    img5.put(0, build_protective_mbr(tot5))
    img5.put(1, bytes(hdr))
    img5.put(2, b5["primary_entries"])
    img5.put(b5["backup_entries_lba"], b5["backup_entries"])
    bak = bytearray(b5["backup_header"])
    struct.pack_into("<I", bak, 20, 0xDEADBEEF)
    struct.pack_into("<I", bak, 16, 0)
    struct.pack_into("<I", bak, 16, crc32(bytes(bak[:92])))
    img5.put(b5["backup_header_lba"], bytes(bak))
    d, r = _scan_file(p5)
    check("T5 GPT with a non-zero reserved dword parses", r.gpt_p["valid"], r.gpt_p["errors"])
    d.close()
    sha_pristine = img5.sha()
    img5.zero(1, 33)                        # destroy the primary GPT
    rc, jp = _apply(p5, "gpt-restore-primary")
    check("T5 restore-primary applied", rc == EXIT_OK, rc)
    check("T5 disk is byte-identical to the pristine image",
          img5.sha() == sha_pristine)
    restored = img5.read(1, 1)
    check("T5 reserved dword preserved verbatim",
          u32(restored, 20) == 0xDEADBEEF, hex(u32(restored, 20)))
    check("T5 header size / revision preserved",
          u32(restored, 12) == 92 and u32(restored, 8) == 0x00010000)

    # ================================================================== T6 ==
    # gpt-fix-crc touches one sector only, and refuses on implausible entries
    img5.put(1, bytes(bytearray(img5.read(1, 1))[:16] + b"\x00\x00\x00\x00" +
                      bytes(bytearray(img5.read(1, 1))[20:])))   # break header CRC
    act, reasons = _build(p5, "gpt-fix-crc")
    check("T6 gpt-fix-crc builds", act is not None, reasons)
    if act:
        check("T6 it patches exactly one sector", len(act.patches) == 1
              and len(act.patches[0].new) == 512, len(act.patches))
        check("T6 it is classified SAFE_RESTORE", act.gate == GATE_SAFE)
    rc, _ = _apply(p5, "gpt-fix-crc")
    d, r = _scan_file(p5)
    check("T6 header CRC repaired", r.gpt_p["valid"], r.gpt_p["errors"])
    check("T6 entry array untouched", img5.read(2, 32) == b5["primary_entries"])
    d.close()
    # now corrupt an entry so the array becomes implausible, and try again
    arr = bytearray(img5.read(2, 32))
    struct.pack_into("<Q", arr, 40, tot5 + 999999)   # entry ends past the disk
    img5.put(2, bytes(arr))
    act, reasons = _build(p5, "gpt-fix-crc")
    check("T6b refuses to bless an implausible entry array", act is None,
          "action was built anyway")
    check("T6b reason mentions the entry array",
          bool(reasons) and any("منطقی نیست" in x for x in reasons), reasons)

    # ================================================================== T7 ==
    # Journal is written BEFORE the first byte, and a partial run is undoable
    p7 = os.path.join(tmp, "tx.img")
    img7 = _Img(p7, 16 * MIB)
    bk = tempfile.mkdtemp(prefix="ddtx_")
    d = RawDisk(p7, writable=False)
    pa = Patch(0, b"\xA1" * 512, "first")
    pb = Patch(4096, b"\xB2" * 512, "second")
    pb.old = b"\xEE" * 512                   # deliberately stale -> must abort
    tx = PatchTransaction(d, "unit-test", [pa, pb], bk)
    jpath = tx.begin()
    j0 = load_journal(jpath)
    check("T7 journal exists before any write", os.path.exists(jpath))
    check("T7 journal state is 'open' pre-write", j0["state"] == "open", j0["state"])
    check("T7 all patches start as pending",
          all(x["status"] == "pending" for x in j0["patches"]))
    d.reopen(writable=True)
    failed = False
    try:
        tx.run()
    except DiskError:
        failed = True
    d.close()
    j1 = load_journal(jpath)
    check("T7 stale patch aborts the transaction", failed)
    check("T7 journal state becomes 'partial'", j1["state"] == "partial", j1["state"])
    check("T7 first patch recorded as done", j1["patches"][0]["status"] == "done",
          j1["patches"][0]["status"])
    check("T7 second patch recorded as failed", j1["patches"][1]["status"] == "failed",
          j1["patches"][1]["status"])
    check("T7 the first patch really landed", img7.read(0, 1)[:4] == b"\xA1" * 4)
    undo_journal(jpath)
    check("T7 partial undo reverts exactly what was written",
          img7.read(0, 1) == bytes(512))
    check("T7 journal marked rolled_back",
          load_journal(jpath)["state"] == "rolled_back")

    # ================================================================== T8 ==
    # Hard gate: no strong candidate -> no rebuild, with an explicit reason
    p8 = os.path.join(tmp, "no_proof.img")
    img8 = _Img(p8, 64 * MIB)
    img8.put(2048, _mk_ntfs_vbr(40960, hidden=2048))     # primary only, no mirror
    img8.zero(0, 1)
    d, r = _scan_file(p8, deep=True)
    cand = [c for c in r.carved if c.start == 2048]
    check("T8 candidate is found", len(cand) == 1, [c.start for c in r.carved])
    if cand:
        check("T8 but its extent is not proven",
              not cand[0].ev.extent_verified, cand[0].ev.extent_source)
        check("T8 and it is blocked", any(k == "extent_unverified"
                                          for k, _ in cand[0].ev.blockers))
    check("T8 strong_candidates() returns nothing", strong_candidates(r) == [])
    d.close()
    act, reasons = _build(p8, "mbr-rebuild")
    check("T8 mbr-rebuild is BLOCKED", act is None)
    check("T8 the reason names the missing proof",
          bool(reasons) and any("strong" in x or "طول" in x for x in reasons), reasons)
    rc, _ = _apply(p8, "mbr-rebuild")
    check("T8 apply returns EXIT_BLOCKED", rc == EXIT_BLOCKED, rc)
    check("T8 nothing was written", img8.read(0, 1) == bytes(512))

    # ================================================================== T9 ==
    # With proof present, the rebuild is allowed and correct
    p9 = os.path.join(tmp, "rebuildable.img")
    img9 = _Img(p9, 128 * MIB)
    _put_ntfs(img9, 2048, 65536)
    _put_exfat(img9, 131072, 65536)
    img9.zero(0, 1)
    d, r = _scan_file(p9, deep=True)
    strong = strong_candidates(r)
    check("T9 two strong candidates", len(strong) == 2,
          [(c.start, c.level, c.ev.extent_source) for c in r.carved])
    d.close()
    rc, jp9 = _apply(p9, "mbr-rebuild")
    check("T9 mbr-rebuild applied", rc == EXIT_OK, rc)
    d, r = _scan_file(p9)
    check("T9 table now describes both volumes",
          [(x.start, x.sectors, x.fs_name()) for x in r.parts] ==
          [(2048, 65536, "NTFS"), (131072, 65536, "exFAT")],
          [(x.start, x.sectors, x.fs_name()) for x in r.parts])
    d.close()
    undo_journal(jp9)
    check("T9 undo removes the table again", img9.read(0, 1) == bytes(512))

    # ================================================================= T10 ==
    # --apply alone is not enough for an inferred rebuild
    rc, _ = _apply(p9, "gpt-rebuild", allow_inferred=False)
    check("T10 inferred rebuild refused without --allow-inferred",
          rc == EXIT_BLOCKED, rc)
    check("T10 still nothing written", img9.read(0, 1) == bytes(512))

    # ================================================================= T11 ==
    # Unknown filesystem must not be guessed as 0x07
    p11 = os.path.join(tmp, "unknown_fs.img")
    img11 = _Img(p11, 64 * MIB)
    _put_ntfs(img11, 2048, 20480)
    blob = bytearray(512)
    blob[510:512] = b"\x55\xAA"
    img11.put(40960, bytes(blob))
    m = bytearray(512)
    m[0x1BE:0x1CE] = build_mbr_entry(0x07, 2048, 20480, True)
    m[0x1CE:0x1DE] = build_mbr_entry(0x07, 40960, 20480)
    m[510:512] = b"\x55\xAA"
    img11.put(0, bytes(m))
    d, r = _scan_file(p11)
    unknown = [x for x in r.parts if x.start == 40960]
    check("T11 the unknown region is not promoted to a real filesystem",
          unknown and unknown[0].fs_name().startswith("unknown"),
          unknown[0].fs_name() if unknown else None)
    check("T11 and it is not a strong candidate",
          all(x.start != 40960 for x in strong_candidates(r)))
    d.close()

    # ================================================================= T12 ==
    # Geometry mismatch is a disk-level blocker; only gpt-fix-geometry passes
    p12 = os.path.join(tmp, "grown.img")
    img12 = _Img(p12, 128 * MIB)
    tot12 = (128 * MIB) // 512
    _put_ntfs(img12, 2048, 100000)
    b12 = build_gpt(tot12, 512, [{"first": 2048, "last": 2048 + 100000 - 1,
                                  "type_guid": GUID_MSDATA, "name": "d"}])
    img12.put(0, build_protective_mbr(tot12))
    img12.put(1, b12["primary_header"])
    img12.put(2, b12["primary_entries"])
    img12.put(b12["backup_entries_lba"], b12["backup_entries"])
    img12.put(b12["backup_header_lba"], b12["backup_header"])
    with open(p12, "r+b") as f:
        f.truncate(192 * MIB)               # the VMDK extent was wrong
    d, r = _scan_file(p12)
    check("T12 geometry mismatch is a disk blocker",
          "geometry_mismatch" in r.blocker_keys(), r.blocker_keys())
    check("T12 gpt-rebuild is gated off", probe_gate(d, r, "gpt-rebuild") == GATE_BLOCKED)
    check("T12 gpt-fix-geometry is exempt",
          probe_gate(d, r, "gpt-fix-geometry") != GATE_BLOCKED)
    d.close()
    rc, _ = _apply(p12, "gpt-rebuild")
    check("T12 rebuild blocked at execution too", rc == EXIT_BLOCKED, rc)
    rc, _ = _apply(p12, "gpt-fix-geometry")
    check("T12 geometry fix applied", rc == EXIT_OK, rc)
    d, r = _scan_file(p12)
    check("T12 mismatch cleared", "geometry_mismatch" not in r.blocker_keys()
          and r.gpt_p["valid"] and r.gpt_b["valid"], r.gpt_p["errors"])
    d.close()

    # ================================================================= T13 ==
    # vbr-restore only with a mirror that validates against the extent
    p13 = os.path.join(tmp, "ntfs_dead_vbr.img")
    img13 = _Img(p13, 64 * MIB)
    _put_ntfs(img13, 2048, 40960)
    good = img13.read(2048, 1)
    img13.put(0, bytes(bytearray(512)))
    m = bytearray(512)
    m[0x1BE:0x1CE] = build_mbr_entry(0x07, 2048, 40960, True)
    m[510:512] = b"\x55\xAA"
    img13.put(0, bytes(m))
    img13.zero(2048)
    d, r = _scan_file(p13)
    num = r.parts[0].num
    mir = find_validated_mirror(d, r.parts[0])
    check("T13 mirror validated against the partition span",
          mir and mir["ok"], mir["reasons"] if mir else None)
    d.close()
    rc, jp13 = _apply(p13, "vbr-restore", part=num)
    check("T13 vbr-restore applied", rc == EXIT_OK, rc)
    check("T13 boot sector byte-identical to the mirror", img13.read(2048, 1) == good)
    d, r = _scan_file(p13)
    check("T13 volume is healthy again", r.parts[0].level == "strong",
          r.parts[0].level)
    d.close()

    # mirror that belongs to a different span must be refused
    p13b = os.path.join(tmp, "bad_mirror.img")
    img13b = _Img(p13b, 64 * MIB)
    img13b.put(2048 + 30000, _mk_ntfs_vbr(40960, hidden=2048))
    m = bytearray(512)
    m[0x1BE:0x1CE] = build_mbr_entry(0x07, 2048, 30001, True)
    m[510:512] = b"\x55\xAA"
    img13b.put(0, bytes(m))
    d, r = _scan_file(p13b)
    mir = find_validated_mirror(d, r.parts[0])
    check("T13b mismatched mirror is rejected", mir and not mir["ok"],
          mir["checks"] if mir else None)
    d.close()
    rc, _ = _apply(p13b, "vbr-restore", part=1)
    check("T13b vbr-restore blocked", rc == EXIT_BLOCKED, rc)
    check("T13b nothing written to the volume start",
          img13b.read(2048, 1) == bytes(512))

    # ================================================================= T14 ==
    # ReFS: the volume header copy at the end of the volume is real evidence.
    # v1.1 hard-coded "ReFS has no mirror" and was wrong; this pins the fix.
    p14 = os.path.join(tmp, "refs.img")
    img14 = _Img(p14, 256 * MIB)
    part_start, part_sectors = 32768, (256 * MIB) // 512 - 32768 - 4063
    vol_sectors = part_sectors - 2048          # ReFS need not fill the partition
    _put_refs(img14, part_start, vol_sectors)
    m = bytearray(512)
    m[0x1BE:0x1CE] = build_mbr_entry(0x07, part_start, part_sectors, True)
    m[510:512] = b"\x55\xAA"
    img14.put(0, bytes(m))
    d, r = _scan_file(p14)
    ev14 = r.parts[0].ev
    check("T14 ReFS detected", r.parts[0].fs_name() == "ReFS")
    check("T14 FSRS parsed at the real offset 0x10",
          r.parts[0].fs["fields"]["total_sectors"] == vol_sectors,
          r.parts[0].fs["fields"])
    check("T14 volume header copy found at the end of the volume",
          ev14.signals["mirror_signature"]["value"],
          ev14.signals["mirror_signature"]["why"])
    check("T14 the copy proves the volume length",
          (ev14.extent_source or "").startswith("ReFS volume header copy"),
          ev14.extent_source)
    check("T14 a ReFS volume shorter than its partition is not a failure",
          ev14.signals["extent_agreement"]["value"],
          ev14.signals["extent_agreement"]["why"])
    check("T14 healthy ReFS reaches level strong", r.parts[0].level == "strong",
          (r.parts[0].level, ev14.confidence))
    check("T14 superblock corroboration found",
          ev14.signals["refs_superblock"]["value"])
    num14 = r.parts[0].num
    plans14 = suggest_plans(d, r)
    check("T14 a healthy ReFS volume gets no repair suggestion",
          not any(x["action"] == "refsutil" for x in plans14),
          [x["action"] for x in plans14])
    d.close()
    act, reasons = _build(p14, "vbr-restore", part=num14)
    check("T14 sector-level repair on ReFS is still refused", act is None)
    check("T14 refusal points at refsutil",
          bool(reasons) and any("refsutil" in x for x in reasons), reasons)

    # ================================================================= T21 ==
    # Regression: layout that combines an MSR partition, a saturated
    # protective-MBR sector count, and a side-aware GPT backup header — the
    # combination that previously produced false disk-level blockers.
    p21 = os.path.join(tmp, "msr_layout.img")
    img21 = _Img(p21, 256 * MIB)
    tot21 = (256 * MIB) // 512
    msr_start, msr_end = 34, 32767
    dat_start = 32768
    dat_end = tot21 - 4064
    vol_sectors = (dat_end - dat_start + 1) - 2048
    _put_refs(img21, dat_start, vol_sectors)
    ents21 = [{"first": msr_start, "last": msr_end, "type_guid": GUID_MSR,
               "name": "Microsoft reserved partition"},
              {"first": dat_start, "last": dat_end, "type_guid": GUID_MSDATA,
               "name": "Basic data partition"}]
    b21 = build_gpt(tot21, 512, ents21)
    pm = bytearray(build_protective_mbr(tot21))
    # the saturated sector count a real protective MBR carries on big disks
    struct.pack_into("<I", pm, 0x1BE + 12, 0xFFFFFFFF)
    img21.put(0, bytes(pm))
    img21.put(1, b21["primary_header"])
    img21.put(2, b21["primary_entries"])
    img21.put(b21["backup_entries_lba"], b21["backup_entries"])
    img21.put(b21["backup_header_lba"], b21["backup_header"])
    d, r = _scan_file(p21)
    check("T21 saturated protective MBR is not an out-of-range error",
          r.mbr["out_of_range"] == 0, r.mbr["out_of_range"])
    check("T21 no false disk-level blocker", r.blocker_keys() == [], r.blocker_keys())
    check("T21 backup GPT AlternateLBA=1 is correct, not a mismatch",
          not r.gpt_b.get("geometry_mismatch"), r.gpt_b["errors"])
    check("T21 primary GPT has no geometry complaint",
          not r.gpt_p.get("geometry_mismatch"), r.gpt_p["errors"])
    msr = [x for x in r.parts if x.start == msr_start]
    check("T21 MSR partition recognised", len(msr) == 1)
    if msr:
        check("T21 MSR is not treated as damaged",
              msr[0].ev.signals["vbr_signature"]["value"] is True,
              msr[0].ev.signals["vbr_signature"]["why"])
        check("T21 MSR is not reported as RAW",
              not any("#%d" % msr[0].num in w and "RAW" in w for w in r.warnings),
              r.warnings)
    plans21 = [x["action"] for x in suggest_plans(d, r)]
    check("T21 nothing is suggested for a healthy disk",
          "vbr-restore" not in plans21 and "refsutil" not in plans21, plans21)
    check("T21 the ReFS volume is strong",
          [x.level for x in r.parts if x.start == dat_start] == ["strong"],
          [(x.start, x.level) for x in r.parts])
    d.close()

    # ================================================================= T22 ==
    # Triage verdicts. Four damage patterns, four different conclusions.
    def _pseudo(seed, size):
        buf = bytearray()
        h = hashlib.sha256(("seed%d" % seed).encode()).digest()
        while len(buf) < size:
            h = hashlib.sha256(h).digest()
            buf += h
        return bytes(buf[:size])

    noise = _pseudo(7, MIB)
    check("T22 test noise carries no filesystem signature",
          not any(sig in noise for sig, _ in FORENSIC_SIGS))

    targs = _fake_args(triage=True, triage_samples=200, triage_tail_mib=32,
                       triage_edge_gib=1)

    def _triage_one(path, start, end):
        dd = RawDisk(path, writable=False)
        try:
            rr = scan(dd)
            pp = [x for x in rr.all_parts if x.start == start]
            if not pp:
                pp = [Part(start, end - start + 1, "MANUAL")]
                pp[0].fs = probe_partition_fs(dd, pp[0])
                pp[0].ev = build_evidence(dd, pp[0])
            return triage_partition(dd, pp[0], targs)
        finally:
            dd.close()

    # (a) boot sector wiped, everything else intact
    pa = os.path.join(tmp, "tri_boot.img")
    ia = _Img(pa, 192 * MIB)
    a_start = 2048
    a_end = (192 * MIB) // 512 - 2048
    a_vol = (a_end - a_start + 1) - 2048
    _put_refs(ia, a_start, a_vol)
    ia.zero(a_start)
    m = bytearray(512)
    m[0x1BE:0x1CE] = build_mbr_entry(0x07, a_start, a_end - a_start + 1, True)
    m[510:512] = b"\x55\xAA"
    ia.put(0, bytes(m))
    ta = _triage_one(pa, a_start, a_end)
    check("T22a wiped boot sector detected", ta["first_sector_zero"])
    check("T22a ReFS header copy recovered from the end",
          ta["refs_header_copy"] and ta["refs_header_copy"]["self_consistent"],
          ta["refs_header_copy"])
    check("T22a true volume length recovered",
          ta["refs_header_copy"]["num_sectors"] == a_vol,
          ta["refs_header_copy"])
    check("T22a verdict = surface damage",
          "سطحی" in ta["verdict"]["label"], ta["verdict"]["label"])
    check("T22a next step points at refsutil",
          any("refsutil" in s for s in ta["verdict"]["next_steps"]),
          ta["verdict"]["next_steps"])

    # (b) the head of the volume was overwritten with foreign data
    pb = os.path.join(tmp, "tri_head.img")
    ib = _Img(pb, 192 * MIB)
    _put_refs(ib, a_start, a_vol)
    for i in range(80):
        ib.put(a_start + i * 2048, noise)
    ib.put(0, bytes(m))
    tb = _triage_one(pb, a_start, a_end)
    check("T22b first sector is foreign data, not zeros",
          not tb["first_sector_zero"] and tb["first_sector_entropy"] > 7.0,
          tb["first_sector_entropy"])
    check("T22b verdict = head overwritten",
          "ابتدای ولوم" in tb["verdict"]["label"], tb["verdict"]["label"])
    check("T22b damage size is reported",
          tb.get("first_structure", {}).get("bad_head_bytes", 0) > 32 * MIB,
          tb.get("first_structure"))

    # (c) the whole volume is foreign high-entropy data
    pc = os.path.join(tmp, "tri_all.img")
    ic = _Img(pc, 192 * MIB)
    for i in range(0, 190):
        ic.put(a_start + i * 2048, noise)
    ic.put(0, bytes(m))
    tc = _triage_one(pc, a_start, a_end)
    check("T22c verdict = widespread overwrite / extent mapping",
          "بازنویسی گسترده" in tc["verdict"]["label"], tc["verdict"]["label"])
    check("T22c next step points back at the VMDK extents",
          any("VMDK" in s for s in tc["verdict"]["next_steps"]),
          tc["verdict"]["next_steps"])

    # (d) the volume is empty
    pd_ = os.path.join(tmp, "tri_zero.img")
    id_ = _Img(pd_, 192 * MIB)
    id_.put(0, bytes(m))
    td = _triage_one(pd_, a_start, a_end)
    check("T22d verdict = effectively empty",
          "خالی" in td["verdict"]["label"], td["verdict"]["label"])

    # ================================================================= T23 ==
    # --deep-ignore-table finds a volume hidden inside a wrong table entry
    p23 = os.path.join(tmp, "wrong_table.img")
    img23 = _Img(p23, 128 * MIB)
    _put_ntfs(img23, 131072, 65536)              # the real volume
    m23 = bytearray(512)                          # a table that claims the disk
    m23[0x1BE:0x1CE] = build_mbr_entry(0x07, 2048, 260096, True)
    m23[510:512] = b"\x55\xAA"
    img23.put(0, bytes(m23))
    d = RawDisk(p23)
    r_norm = scan(d, deep=True, deep_step=512)
    r_ign = scan(d, deep=True, deep_step=512, ignore_table=True)
    found_norm = any(c.start == 131072 for c in r_norm.carved)
    found_ign = any(c.start == 131072 for c in r_ign.carved)
    check("T23 the hidden volume is missed while trusting the table",
          not found_norm, [c.start for c in r_norm.carved])
    check("T23 --deep-ignore-table finds it", found_ign,
          [c.start for c in r_ign.carved])
    d.close()

    # ================================================================= T15 ==
    # Imager: unreadable sectors are recorded, never silently zeroed
    class _Flaky(RawDisk):
        bad_from = 4 * MIB
        bad_to = 4 * MIB + 8192

        def read_at(self, offset, length):
            a, b = offset, offset + length
            if a < self.bad_to and b > self.bad_from:
                raise DiskError("simulated media error at %d" % offset)
            return RawDisk.read_at(self, offset, length)

    p15 = os.path.join(tmp, "flaky.img")
    _Img(p15, 16 * MIB)
    fd = _Flaky(p15, writable=False)
    imgpath = os.path.join(tmp, "flaky_copy.img")
    _, badmap = make_image(fd, imgpath, retries=2, fill="pat")
    fd.close()
    check("T15 image is full size", os.path.getsize(imgpath) == 16 * MIB)
    check("T15 badmap records the unreadable span",
          badmap["unreadable_bytes"] == 8192 and len(badmap["bad_ranges"]) == 1,
          (badmap["unreadable_bytes"], badmap["bad_ranges"]))
    check("T15 badmap json written", os.path.exists(imgpath + ".badmap.json"))
    with open(imgpath, "rb") as f:
        f.seek(4 * MIB)
        filler = f.read(64)
    check("T15 filler is a recognisable pattern, not zeros",
          b"DISKDOCTOR-UNREADABLE" in filler, filler[:32])

    # ================================================================= T16 ==
    # 4Kn disk end to end
    p16 = os.path.join(tmp, "4kn.img")
    img16 = _Img(p16, 256 * MIB, sector=4096)
    tot16 = (256 * MIB) // 4096
    vbr = _mk_ntfs_vbr(8192, bps=4096, hidden=256)
    img16.put(256, vbr)
    img16.put(256 + 8192 - 1, vbr)
    b16 = build_gpt(tot16, 4096, [{"first": 256, "last": 256 + 8192 - 1,
                                   "type_guid": GUID_MSDATA, "name": "4kn"}])
    img16.put(0, build_protective_mbr(tot16))
    img16.put(1, b16["primary_header"])
    img16.put(2, b16["primary_entries"])
    img16.put(b16["backup_entries_lba"], b16["backup_entries"])
    img16.put(b16["backup_header_lba"], b16["backup_header"])
    d, r = _scan_file(p16, sector=4096)
    check("T16 4Kn GPT parsed", r.gpt_p["valid"] and r.gpt_b["valid"], r.gpt_p["errors"])
    check("T16 4Kn NTFS is strong", r.parts and r.parts[0].level == "strong",
          [(x.fs_name(), x.level) for x in r.parts])
    d.close()

    # ================================================================= T17 ==
    # BitLocker is a blocker, ext4 is detected, superfloppy still works
    p17 = os.path.join(tmp, "bitlocker.img")
    img17 = _Img(p17, 32 * MIB)
    bl = bytearray(512)
    bl[0:3] = b"\xEB\x58\x90"
    bl[3:11] = b"-FVE-FS-"
    struct.pack_into("<H", bl, 0x0B, 512)
    bl[510:512] = b"\x55\xAA"
    img17.put(2048, bytes(bl))
    m = bytearray(512)
    m[0x1BE:0x1CE] = build_mbr_entry(0x07, 2048, 20480, True)
    m[510:512] = b"\x55\xAA"
    img17.put(0, bytes(m))
    d, r = _scan_file(p17)
    check("T17 BitLocker detected and blocked",
          r.parts[0].fs_name() == "BitLocker" and
          any(k == "encrypted" for k, _ in r.parts[0].ev.blockers))
    d.close()

    p18 = os.path.join(tmp, "ext4.img")
    img18 = _Img(p18, 32 * MIB)
    img18.put(0, bytes(1024) + _mk_ext4_sb())
    d = RawDisk(p18)
    fsi = probe_fs(d.read_at(0, 68 * KIB), 512)
    check("T17b ext4 detected", fsi and fsi["fs"] == "ext4", fsi)
    d.close()

    p19 = os.path.join(tmp, "superfloppy.img")
    img19 = _Img(p19, 32 * MIB)
    _put_fat32(img19, 0, 65536)
    d, r = _scan_file(p19)
    check("T17c superfloppy detected", "Superfloppy" in r.scheme, r.scheme)
    d.close()

    # ================================================================= T18 ==
    # Container detection blocks everything
    p20 = os.path.join(tmp, "fake.vmdk")
    with open(p20, "wb") as f:
        f.write(b"KDMV" + bytes(2 * MIB))
    d, r = _scan_file(p20)
    check("T18 VMDK container detected", "container" in r.blocker_keys(),
          r.blocker_keys())
    d.close()
    rc, _ = _apply(p20, "mbr-rebuild")
    check("T18 all writes blocked on a container", rc == EXIT_BLOCKED, rc)

    # ================================================================= T19 ==
    # check_journals finds an unfinished journal
    rc = check_journals(bk)
    check("T19 journal audit runs", rc == EXIT_OK)

    # ================================================================= T20 ==
    # Deep scan speed
    t0 = time.time()
    d = RawDisk(p5)
    scan(d, deep=True, deep_step=512)
    dt = time.time() - t0
    d.close()
    check("T20 deep scan of 256 MiB under 20s", dt < 20, "%.2fs" % dt)

    # ================================================================= T24 ==
    # --auto : one command, every answer, still zero writes
    p24a = os.path.join(tmp, "auto_healthy.img")
    i24a = _Img(p24a, 192 * MIB)
    _put_ntfs(i24a, 2048, 65536)
    _put_fat32(i24a, 131072, 65536)
    m24 = bytearray(512)
    m24[0x1BE:0x1CE] = build_mbr_entry(0x07, 2048, 65536, True)
    m24[0x1CE:0x1DE] = build_mbr_entry(0x0C, 131072, 65536)
    m24[510:512] = b"\x55\xAA"
    i24a.put(0, bytes(m24))
    sha_a = i24a.sha()

    p24b = os.path.join(tmp, "auto_broken.img")
    i24b = _Img(p24b, 192 * MIB)
    bstart = 2048
    bend = (192 * MIB) // 512 - 2048
    bvol = (bend - bstart + 1) - 2048
    _put_refs(i24b, bstart, bvol)
    i24b.zero(bstart)                      # boot sector gone, structure intact
    mb = bytearray(512)
    mb[0x1BE:0x1CE] = build_mbr_entry(0x07, bstart, bend - bstart + 1, True)
    mb[510:512] = b"\x55\xAA"
    i24b.put(0, bytes(mb))
    sha_b = i24b.sha()

    rep = os.path.join(tmp, "auto_report.txt")
    aargs = _fake_args(auto=True, quiet=True, auto_out=rep, triage=True,
                       triage_samples=96, triage_tail_mib=32, triage_edge_gib=1)

    saved = globals().get("REPORTFILE")
    s_ok = auto_one(p24a, aargs)
    s_bad = auto_one(p24b, aargs)
    globals()["REPORTFILE"] = saved

    check("T24 healthy image is called healthy", s_ok["verdict"] == "سالم",
          s_ok["verdict"])
    check("T24 healthy image needs no repair plan", s_ok["plans"] == [],
          s_ok["plans"])
    check("T24 damaged image is flagged", s_bad["verdict"] != "سالم",
          s_bad["verdict"])
    check("T24 damaged image got a triage verdict",
          s_bad["triage"] and s_bad["triage"][0]["verdict"]["label"],
          s_bad.get("triage"))
    check("T24 triage recovered the true ReFS length",
          (s_bad["triage"][0].get("refs_header_copy") or {}).get("num_sectors") == bvol,
          s_bad["triage"][0].get("refs_header_copy"))
    check("T24 auto wrote nothing to either image",
          i24a.sha() == sha_a and i24b.sha() == sha_b)

    aargs2 = _fake_args(auto=True, quiet=True, auto_out=rep, disk=p24b,
                        triage=True, triage_samples=64, triage_tail_mib=16,
                        triage_edge_gib=1)
    rc24 = auto_run(aargs2)
    check("T24 auto_run completes", rc24 == EXIT_OK, rc24)
    check("T24 text report written", os.path.exists(rep) and
          os.path.getsize(rep) > 500, os.path.getsize(rep) if os.path.exists(rep) else 0)
    jrep = os.path.splitext(rep)[0] + ".json"
    check("T24 json report written", os.path.exists(jrep))
    if os.path.exists(jrep):
        with open(jrep, encoding="utf-8") as f:
            jd = json.load(f)
        check("T24 json carries the per-disk verdict",
              jd["disks"] and jd["disks"][0].get("verdict"), jd.get("disks"))
    with open(rep, encoding="utf-8") as f:
        body = f.read()
    check("T24 report contains the triage section", "TRIAGE" in body)
    check("T24 report is plain text without escape codes", "\x1b[" not in body)

    # ================================================================= T25 ==
    # Regression: a volume full of compressed backup files samples as ~100%
    # high entropy whether it is damaged or not. Entropy must not be treated
    # as evidence of damage on its own.
    def _fill(img, lba_from, lba_to, block):
        with open(img.path, "r+b") as f:
            f.seek(lba_from * img.sector)
            todo = (lba_to - lba_from) * img.sector
            while todo > 0:
                n = min(len(block), todo)
                f.write(block[:n])
                todo -= n

    def _pseudo2(seed, size):
        buf = bytearray()
        h = hashlib.sha256(("s%d" % seed).encode()).digest()
        while len(buf) < size:
            h = hashlib.sha256(h).digest()
            buf += h
        return bytes(buf[:size])

    noise2 = _pseudo2(11, MIB)

    # a HEALTHY ReFS volume that happens to be completely full of compressed
    # data — exactly what a Veeam repository looks like
    p25h = os.path.join(tmp, "full_healthy.img")
    i25h = _Img(p25h, 128 * MIB)
    hs, he = 2048, (128 * MIB) // 512 - 2048
    hvol = (he - hs + 1) - 2048
    _fill(i25h, hs, he, noise2)
    _put_refs(i25h, hs, hvol)
    m25 = bytearray(512)
    m25[0x1BE:0x1CE] = build_mbr_entry(0x07, hs, he - hs + 1, True)
    m25[510:512] = b"\x55\xAA"
    i25h.put(0, bytes(m25))
    d, r = _scan_file(p25h)
    check("T25 the full healthy ReFS volume is still recognised",
          r.parts and r.parts[0].fs_name() == "ReFS"
          and r.parts[0].level == "strong",
          [(x.fs_name(), x.level) for x in r.parts])
    ctl_part = r.parts[0]
    d.close()

    # the same volume with 32 MiB of its head destroyed
    p25d = os.path.join(tmp, "full_damaged.img")
    i25d = _Img(p25d, 128 * MIB)
    _fill(i25d, hs, he, noise2)
    _put_refs(i25d, hs, hvol)
    _fill(i25d, hs, hs + 65536, noise2)          # wipe the first 32 MiB
    i25d.put(0, bytes(m25))

    targs25 = _fake_args(triage_samples=96, triage_tail_mib=16,
                         triage_edge_gib=1, triage_head_gib=1,
                         triage_head_samples=48)
    _CONTROL_CACHE.clear()
    dd_ = RawDisk(p25d, writable=False)
    rr = scan(dd_)
    t_no_ctl = triage_partition(dd_, rr.parts[0], targs25)
    dd_.close()

    check("T25 without a control the entropy body is not called overwritten",
          "بازنویسی گسترده" not in t_no_ctl["verdict"]["label"],
          t_no_ctl["verdict"]["label"])
    check("T25 the head damage is measured instead",
          "ابتدای ولوم" in t_no_ctl["verdict"]["label"],
          (t_no_ctl["verdict"]["label"], t_no_ctl.get("first_structure")))
    check("T25 tail structure is recognised as intact",
          t_no_ctl["refs_header_copy"] and
          t_no_ctl["refs_header_copy"]["self_consistent"])

    # now with the healthy volume supplied as the control
    _CONTROL_CACHE.clear()
    targs25b = _fake_args(triage_samples=96, triage_tail_mib=16,
                          triage_edge_gib=1, triage_head_gib=1,
                          triage_head_samples=48)
    targs25b._control = {"path": p25h, "start": ctl_part.start,
                         "sectors": ctl_part.sectors, "fs": "ReFS"}
    dd_ = RawDisk(p25d, writable=False)
    rr = scan(dd_)
    t_ctl = triage_partition(dd_, rr.parts[0], targs25b)
    dd_.close()
    check("T25 control measurement was taken", t_ctl["control"] is not None,
          t_ctl.get("control"))
    check("T25 control shows the same high entropy",
          t_ctl["control"]["high_entropy"] > 0.5, t_ctl.get("control"))
    check("T25 verdict records that entropy is not informative",
          t_ctl["verdict"]["entropy_informative"] is False,
          t_ctl["verdict"]["entropy_informative"])
    check("T25 verdict text says so explicitly",
          any("تفکیک" in x or "نشانه خرابی نیست" in x
              for x in t_ctl["verdict"]["lines"]), t_ctl["verdict"]["lines"])

    # ================================================================= T26 ==
    # A genuinely overwritten volume, measured against a clean control, still
    # gets called overwritten.
    p26 = os.path.join(tmp, "really_overwritten.img")
    i26 = _Img(p26, 128 * MIB)
    _fill(i26, hs, he, noise2)                   # nothing but foreign data
    i26.put(0, bytes(m25))
    p26c = os.path.join(tmp, "clean_control.img")
    i26c = _Img(p26c, 128 * MIB)
    _put_refs(i26c, hs, hvol)                    # sparse, low-entropy control
    i26c.put(0, bytes(m25))
    d, rc26 = _scan_file(p26c)
    ctl26 = rc26.parts[0]
    d.close()
    _CONTROL_CACHE.clear()
    targs26 = _fake_args(triage_samples=96, triage_tail_mib=16,
                         triage_edge_gib=1, triage_head_gib=1,
                         triage_head_samples=48)
    targs26._control = {"path": p26c, "start": ctl26.start,
                        "sectors": ctl26.sectors, "fs": "ReFS"}
    dd_ = RawDisk(p26, writable=False)
    rr26 = scan(dd_)
    t26 = triage_partition(dd_, rr26.parts[0], targs26)
    dd_.close()
    check("T26 clean control shows low entropy",
          t26["control"]["high_entropy"] < 0.5, t26.get("control"))
    check("T26 a truly overwritten volume is still flagged",
          "بازنویسی گسترده" in t26["verdict"]["label"],
          t26["verdict"]["label"])

    # ================================================================= T27 ==
    # The forward scan must run even when the sampled map found nothing
    p27 = os.path.join(tmp, "no_samples_hit.img")
    i27 = _Img(p27, 192 * MIB)
    _put_refs(i27, hs, hvol)
    for i in range(20):
        i27.put(hs + i * 2048, noise2)
    i27.put(0, bytes(m25))
    _CONTROL_CACHE.clear()
    targs27 = _fake_args(triage_samples=24, triage_tail_mib=16,
                         triage_edge_gib=1, triage_head_gib=1,
                         triage_head_samples=32)
    dd_ = RawDisk(p27, writable=False)
    rr27 = scan(dd_)
    t27 = triage_partition(dd_, rr27.parts[0], targs27)
    dd_.close()
    check("T27 the forward scan ran regardless of the map result",
          "first_structure" in t27, list(t27.keys()))
    check("T27 head map was produced", t27.get("head_map", {}).get("samples", 0) > 0)

    # ================================================================= T28 ==
    # refsutil version-ceiling mismatch must be recognised and explained, not
    # confused with "volume does not contain a recognized file system".
    real_output = (
        "Microsoft ReFS Salvage [Version 10.0.11070]\n"
        "Copyright (c) 2015 Microsoft Corp.\n"
        "Local time: 8/31/2026 11:33:52\n"
        "Option(s) specified: -x\n"
        "ReFS version: 3.14\n"
        "Error: The volume is an unsupported ReFS version. This utility "
        "supports versions up to 3.9. Volume is 3.14.\n"
        "Error: Command failed.\n"
        "Error: The volume does not contain a recognized file system. "
        "Please make sure that all required file system drivers are loaded "
        "and that the volume is not corrupt.\n"
    )
    mm = parse_refsutil_version_mismatch(real_output)
    check("T28 version mismatch is detected from refsutil's own text",
          mm is not None, mm)
    check("T28 volume version parsed correctly",
          mm and mm["volume_version"] == "3.14", mm)
    check("T28 max supported version parsed correctly",
          mm and mm["max_supported"] == "3.9", mm)

    ordinary_fail = (
        "Error: Could not open volume E:.\n"
        "Error: The system cannot find the file specified.\n"
    )
    check("T28b an unrelated failure is not misread as a version mismatch",
          parse_refsutil_version_mismatch(ordinary_fail) is None)

    clean_success = (
        "Microsoft ReFS Salvage [Version 10.0.26100]\n"
        "ReFS version: 3.14\n"
        "Salvage completed successfully.\n"
    )
    check("T28c a normal run (no error) is not flagged as a mismatch",
          parse_refsutil_version_mismatch(clean_success) is None)

    # the plan and warning text must carry the ReFS version so the person can
    # check it against winver before ever calling refsutil
    p28 = os.path.join(tmp, "refs_new_version.img")
    i28 = _Img(p28, 128 * MIB)
    s28, e28 = 2048, (128 * MIB) // 512 - 2048
    v28 = (e28 - s28 + 1) - 2048
    hdr28 = _mk_refs_vbr(v28, major=3, minor=14)
    i28.put(s28, hdr28)
    # a mismatched copy at the end: fs is still detected as ReFS 3.14, but the
    # length cannot be proven, so it needs a plan without being wiped to RAW
    i28.put(s28 + v28 - 1, _mk_refs_vbr(v28 - 500, major=3, minor=14))
    m28 = bytearray(512)
    m28[0x1BE:0x1CE] = build_mbr_entry(0x07, s28, e28 - s28 + 1, True)
    m28[510:512] = b"\x55\xAA"
    i28.put(0, bytes(m28))
    d, r28 = _scan_file(p28)
    plans28 = suggest_plans(d, r28)
    refs_plan = [x for x in plans28 if x["action"] == "refsutil"]
    check("T28d refsutil is suggested for the damaged ReFS 3.14 volume",
          len(refs_plan) == 1, [x["action"] for x in plans28])
    check("T28d the suggestion states the ReFS version",
          refs_plan and "3.14" in refs_plan[0]["why"],
          refs_plan[0]["why"] if refs_plan else None)
    check("T28d disk warnings mention the version ceiling risk",
          any("سقف نسخه" in w for w in r28.warnings), r28.warnings)
    d.close()

    QUIET, EXPLAIN = prev_q, prev_e
    failed = [n for n, okk in results if not okk]
    print("\n%d/%d passed" % (len(results) - len(failed), len(results)))
    if failed:
        print("FAILED: %s" % ", ".join(failed))
        return EXIT_TESTFAIL
    print("test images kept in %s" % tmp)
    return EXIT_OK


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
    global REPORTFILE
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    txt = args.auto_out or ("diskdoctor_report_%s.txt" % ts)
    jsn = os.path.splitext(txt)[0] + ".json"
    try:
        REPORTFILE = open(txt, "w", encoding="utf-8")
    except Exception as e:
        err("cannot open report file: %s" % e)
        REPORTFILE = None

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
    g.add_argument("--force", action="store_true", help="عبور از blockerها")
    g.add_argument("--offline", action="store_true", help="Offline کردن دیسک (ویندوز)")
    g.add_argument("--backup-dir", default="diskdoctor_backups", help="محل Journal")

    g = p.add_argument_group("Journal")
    g.add_argument("--undo", metavar="JOURNAL", help="برگرداندن یک عملیات")
    g.add_argument("--inspect", metavar="JOURNAL", help="نمایش وضعیت یک Journal")
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
    if args.log:
        try:
            LOGFILE = open(args.log, "a", encoding="utf-8")
        except Exception as e:
            err("cannot open log: %s" % e)

    try:
        if args.help_full:
            print(__doc__)
            return EXIT_OK
        if args.self_test:
            return self_test()
        if args.list:
            return print_disk_list()
        if args.inspect:
            inspect_journal(args.inspect)
            return EXIT_OK
        if args.check_journals:
            return check_journals(args.backup_dir)
        if args.undo:
            try:
                undo_journal(args.undo, force=args.force)
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
                           retries=args.image_retries, fill=args.image_fill)
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
            print_plans(disk, r, suggest_plans(disk, r))
            if args.action:
                return execute_action(disk, r, args, args.action)
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
