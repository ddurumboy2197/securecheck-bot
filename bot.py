"""
╔══════════════════════════════════════════╗
║   🔐 SecureCheck Bot — v2.0              ║
║   Telegram Virus Tekshiruvchi            ║
║   70+ antivirus • VirusTotal API v3      ║
╚══════════════════════════════════════════╝

Texnologiyalar: Aiogram 3.x, VirusTotal API v3, aiohttp, aiofiles
"""

import os
import sys
import hashlib
import asyncio
import logging
import tempfile
from pathlib import Path
from datetime import datetime

import aiohttp
import aiofiles
from dotenv import load_dotenv

from aiogram import Bot, Dispatcher, Router, F
from aiogram.types import Message
from aiogram.filters import CommandStart, Command
from aiogram.enums import ParseMode
from aiogram.client.default import DefaultBotProperties

# ═══════════════════════════════════════════════════════
#  ⚙️  KONFIGURATSIYA
# ═══════════════════════════════════════════════════════

load_dotenv()

BOT_TOKEN   = os.getenv("BOT_TOKEN")
VT_API_KEY  = os.getenv("VIRUSTOTAL_API_KEY")

if not BOT_TOKEN:
    sys.exit("❌  BOT_TOKEN topilmadi! .env faylini tekshiring.")
if not VT_API_KEY:
    sys.exit("❌  VIRUSTOTAL_API_KEY topilmadi! .env faylini tekshiring.")

VT_BASE_URL      = "https://www.virustotal.com/api/v3"
VT_HEADERS       = {"x-apikey": VT_API_KEY}
MAX_FILE_SIZE    = 32 * 1024 * 1024   # 32 MB
POLL_INTERVAL    = 15                  # soniya
MAX_POLL_ATTEMPTS = 40                 # 40 × 15s = 10 daqiqa

REQUEST_SEMAPHORE  = asyncio.Semaphore(1)
RATE_LIMIT_DELAY   = 15.0

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(levelname)-8s │ %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("SecureCheck")

bot    = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
router = Router()
dp     = Dispatcher()
dp.include_router(router)

TEMP_DIR = Path(tempfile.gettempdir()) / "securecheck"
TEMP_DIR.mkdir(exist_ok=True)


# ═══════════════════════════════════════════════════════
#  🌐  VIRUSTOTAL API
# ═══════════════════════════════════════════════════════

async def _rate_limited_request(
    method: str, url: str, session: aiohttp.ClientSession, **kwargs
) -> dict | None:
    async with REQUEST_SEMAPHORE:
        try:
            async with session.request(method, url, headers=VT_HEADERS, **kwargs) as resp:
                if resp.status == 200:
                    return await resp.json()
                elif resp.status == 404:
                    return None
                elif resp.status == 429:
                    logger.warning("⚠️  Rate limit! 60 soniya kutilmoqda...")
                    await asyncio.sleep(60)
                    async with session.request(method, url, headers=VT_HEADERS, **kwargs) as r2:
                        return await r2.json() if r2.status == 200 else None
                else:
                    logger.error(f"VT API xato: {resp.status} — {await resp.text()}")
                    return None
        finally:
            await asyncio.sleep(RATE_LIMIT_DELAY)


async def check_hash(sha256: str, session: aiohttp.ClientSession) -> dict | None:
    logger.info(f"🔍  Hash: {sha256[:16]}…")
    return await _rate_limited_request("GET", f"{VT_BASE_URL}/files/{sha256}", session)


async def upload_file(file_path: Path, session: aiohttp.ClientSession) -> str | None:
    logger.info(f"📤  Yuklanmoqda: {file_path.name}")
    data = aiohttp.FormData()
    async with aiofiles.open(file_path, "rb") as f:
        data.add_field("file", await f.read(), filename=file_path.name)
    result = await _rate_limited_request("POST", f"{VT_BASE_URL}/files", session, data=data)
    if result and "data" in result:
        aid = result["data"]["id"]
        logger.info(f"✅  Yuklandi. ID: {aid}")
        return aid
    return None


async def get_analysis(analysis_id: str, session: aiohttp.ClientSession) -> dict | None:
    return await _rate_limited_request("GET", f"{VT_BASE_URL}/analyses/{analysis_id}", session)


async def poll_analysis(analysis_id: str, session: aiohttp.ClientSession) -> dict | None:
    for attempt in range(1, MAX_POLL_ATTEMPTS + 1):
        result = await get_analysis(analysis_id, session)
        if result and "data" in result:
            if result["data"]["attributes"].get("status") == "completed":
                logger.info(f"✅  Tahlil tugadi ({attempt}-urinish)")
                return result
            logger.info(f"⏳  Davom etmoqda… ({attempt}/{MAX_POLL_ATTEMPTS})")
        await asyncio.sleep(POLL_INTERVAL)
    logger.warning("⏰  Tahlil vaqti tugadi!")
    return None


# ═══════════════════════════════════════════════════════
#  🔢  SHA-256
# ═══════════════════════════════════════════════════════

async def compute_sha256(file_path: Path) -> str:
    h = hashlib.sha256()
    async with aiofiles.open(file_path, "rb") as f:
        while chunk := await f.read(8192):
            h.update(chunk)
    return h.hexdigest()


# ═══════════════════════════════════════════════════════
#  🎨  DIZAYN YORDAMCHI FUNKSIYALAR
# ═══════════════════════════════════════════════════════

def _bar(malicious: int, total: int, length: int = 16) -> str:
    """Rang-barang progress bar."""
    if total == 0:
        return "░" * length
    ratio  = malicious / total
    filled = int(ratio * length)
    empty  = length - filled

    if malicious >= 4:
        return "█" * filled + "░" * empty   # qizil zona
    elif malicious >= 1:
        return "▓" * filled + "░" * empty   # to'q sariq zona
    elif filled > 0:
        return "▒" * filled + "░" * empty   # sariq zona
    return "░" * length                      # yashil zona


def _threat_badge(malicious: int, suspicious: int) -> tuple[str, str, str, str]:
    """
    Xavf darajasi.
    Qaytaradi: (qisqa_nom, uzun_nom, rang_emoji, tavsiya_matni)
    """
    if malicious >= 4:
        return (
            "XAVFLI",
            "🔴 JIDDIY XAVFLI",
            "🔴",
            "⛔️ <b>HECH QACHON ochmang!</b>\n"
            "     Faylni <b>darhol o'chiring</b> — qurilmangiz\n"
            "     va shaxsiy ma'lumotlaringiz xavf ostida."
        )
    elif malicious >= 1 or suspicious >= 2:
        return (
            "SHUBHALI",
            "🟠 SHUBHALI FAYL",
            "🟠",
            "⚠️ <b>Ochmang!</b> Manbani ehtiyotkorlik bilan\n"
            "     tekshiring. Faqat to'liq ishonchli bo'lsangiz\n"
            "     va zarurat bo'lsagina foydalaning."
        )
    elif suspicious >= 1:
        return (
            "EHTIYOT",
            "🟡 OZGINA SHUBHALI",
            "🟡",
            "⚠️ <b>Ehtiyot bo'ling.</b> Bir nechta antivirus\n"
            "     shubhali belgilar topgan. Ishonchli\n"
            "     manbadan kelganiga ishonch hosil qiling."
        )
    else:
        return (
            "XAVFSIZ",
            "🟢 XAVFSIZ",
            "🟢",
            "✅ <b>Ochishingiz mumkin.</b>\n"
            "     70+ antivirus faylda hech qanday\n"
            "     xavf topmadi. Shunga qaramay ehtiyot bo'ling."
        )


def _size_str(size_bytes: int) -> str:
    if size_bytes >= 1_048_576:
        return f"{size_bytes / 1_048_576:.2f} MB"
    elif size_bytes >= 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes} B"


# ═══════════════════════════════════════════════════════
#  📋  NATIJA XABARI
# ═══════════════════════════════════════════════════════

def format_result(file_name: str, sha256: str, stats: dict, source: str) -> str:
    malicious   = stats.get("malicious",   0)
    suspicious  = stats.get("suspicious",  0)
    undetected  = stats.get("undetected",  0)
    harmless    = stats.get("harmless",    0)
    total       = malicious + suspicious + undetected + harmless

    _, long_name, dot, advice = _threat_badge(malicious, suspicious)
    bar  = _bar(malicious, total)
    now  = datetime.now().strftime("%d.%m.%Y • %H:%M")

    # Foiz hisoblash
    pct = f"{malicious / total * 100:.0f}%" if total else "—"

    return (
        f"┌{'─' * 34}┐\n"
        f"│  🔐  <b>SecureCheck — Tekshiruv Natijasi</b>  │\n"
        f"└{'─' * 34}┘\n\n"

        f"📄  <b>Fayl:</b>  <code>{file_name}</code>\n"
        f"🔑  <b>SHA-256:</b>  <code>{sha256[:12]}…{sha256[-6:]}</code>\n"
        f"📡  <b>Manba:</b>  {source}\n\n"

        f"╔{'═' * 32}╗\n"
        f"║   📊  TAHLIL NATIJALARI{' ' * 10}║\n"
        f"╠{'═' * 32}╣\n"
        f"║                                ║\n"
        f"║  {bar}  {pct:<5}  ║\n"
        f"║                                ║\n"
        f"║  🔴 Xavfli:    <b>{malicious:<4}</b> ta antivirus  ║\n"
        f"║  🟠 Shubhali:  <b>{suspicious:<4}</b> ta antivirus  ║\n"
        f"║  🟢 Xavfsiz:   <b>{undetected + harmless:<4}</b> ta antivirus  ║\n"
        f"║  📋 Jami:      <b>{total:<4}</b> ta antivirus  ║\n"
        f"║                                ║\n"
        f"╚{'═' * 32}╝\n\n"

        f"🏷  <b>XULOSA:</b>  {long_name}\n\n"

        f"💬  <b>Tavsiya:</b>\n"
        f"{advice}\n\n"

        f"🕐  <i>{now}</i>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔐  <i>SecureCheck — Xavfsizligingiz Bizning Maqsadimiz</i>"
    )


# ═══════════════════════════════════════════════════════
#  📨  BOT HANDLERLARI
# ═══════════════════════════════════════════════════════

@router.message(CommandStart())
async def cmd_start(message: Message):
    name = message.from_user.first_name
    await message.answer(
        f"┌{'─' * 36}┐\n"
        f"│   🔐  <b>SecureCheck — Virus Tekshiruv</b>   │\n"
        f"└{'─' * 36}┘\n\n"

        f"Assalomu alaykum, <b>{name}</b>! 👋\n\n"
        f"Men sizga har qanday faylni\n"
        f"<b>70+ antivirus</b> dvigateli bilan tekshirib beraman.\n\n"

        f"╔{'═' * 30}╗\n"
        f"║   📌  QANDAY ISHLATILADI?         ║\n"
        f"╠{'═' * 30}╣\n"
        f"║                              ║\n"
        f"║  1️⃣  Faylni menga yuboring   ║\n"
        f"║  2️⃣  70+ antivirus tekshiradi ║\n"
        f"║  3️⃣  Batafsil hisobot olasiz  ║\n"
        f"║                              ║\n"
        f"╚{'═' * 30}╝\n\n"

        f"📎  <b>Qo'llab-quvvatlanadi:</b>\n"
        f"  ├ 💾  Dasturlar: <code>.exe .apk .msi</code>\n"
        f"  ├ 🗜  Arxivlar: <code>.zip .rar .7z .tar</code>\n"
        f"  ├ 📝  Hujjatlar: <code>.pdf .docx .xlsx</code>\n"
        f"  ├ ⚙️  Skriptlar: <code>.py .js .bat .ps1</code>\n"
        f"  └ 📦  Barcha boshqa fayl turlari\n\n"

        f"⚠️  <b>Cheklov:</b>  Fayl hajmi ≤ <b>32 MB</b>\n\n"

        f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"💡  /help — Batafsil yordam\n"
        f"🔐  <i>Xavfsizligingiz Bizning Maqsadimiz!</i>"
    )


@router.message(Command("help"))
async def cmd_help(message: Message):
    await message.answer(
        f"┌{'─' * 34}┐\n"
        f"│   🔐  <b>SecureCheck — Yordam Markazi</b>   │\n"
        f"└{'─' * 34}┘\n\n"

        f"📖  <b>Bot haqida:</b>\n"
        f"SecureCheck — VirusTotal orqali fayllarni\n"
        f"<b>70+ antivirus</b> dvigateli bilan tekshiradigan\n"
        f"Telegram xavfsizlik yordamchisi.\n\n"

        f"╔{'═' * 30}╗\n"
        f"║   🚦  XAVF DARAJALARI             ║\n"
        f"╠{'═' * 30}╣\n"
        f"║                              ║\n"
        f"║  🔴  <b>XAVFLI</b>               ║\n"
        f"║      4+ antivirus topgan     ║\n"
        f"║      ⛔️ Hech qachon ochmang  ║\n"
        f"║                              ║\n"
        f"║  🟠  <b>SHUBHALI</b>             ║\n"
        f"║      1–3 antivirus topgan    ║\n"
        f"║      ⚠️ Ochmang, tekshiring  ║\n"
        f"║                              ║\n"
        f"║  🟡  <b>OZGINA SHUBHALI</b>      ║\n"
        f"║      Shubhali belgilar bor   ║\n"
        f"║      ⚠️ Ehtiyot bo'ling      ║\n"
        f"║                              ║\n"
        f"║  🟢  <b>XAVFSIZ</b>              ║\n"
        f"║      Hech kim topmagan       ║\n"
        f"║      ✅ Ochishingiz mumkin   ║\n"
        f"║                              ║\n"
        f"╚{'═' * 30}╝\n\n"

        f"📊  <b>Aniqlik darajasi:</b>\n"
        f"  ├ 🔵  Ma'lum viruslar:   <b>97–100%</b>\n"
        f"  └ 🟣  Yangi (0-day):     <b>20–40%</b>\n\n"

        f"⚙️  <b>Cheklovlar:</b>\n"
        f"  ├ 📦  Max hajm: <b>32 MB</b>\n"
        f"  ├ 📆  Kunlik limit: <b>500 so'rov</b>\n"
        f"  └ 🔒  Parollik arxivlar tekshirilmaydi\n\n"

        f"⚖️  <b>Eslatma:</b>\n"
        f"Bot <b>100% kafolat bermaydi</b>. Yakuniy\n"
        f"xavfsizlik mas'uliyati siz zimmangizdadir.\n\n"

        f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔐  <i>SecureCheck — Xavfsizligingiz Bizning Maqsadimiz</i>"
    )


# ─── Status xabarlari ─────────────────────────────────

def _status(file_name: str, step: str, detail: str = "") -> str:
    """Umumiy progress xabari shablon."""
    return (
        f"┌{'─' * 34}┐\n"
        f"│   ⏳  <b>Tekshiruv Jarayoni</b>            │\n"
        f"└{'─' * 34}┘\n\n"
        f"📄  <b>Fayl:</b>  <code>{file_name}</code>\n\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"{step}\n"
        + (f"\n<i>{detail}</i>" if detail else "")
    )


@router.message(F.document)
async def handle_document(message: Message):
    document  = message.document
    file_name = document.file_name or "nomalum_fayl"
    file_size = document.file_size or 0

    # ── Hajm tekshiruvi ────────────────────────────────
    if file_size > MAX_FILE_SIZE:
        await message.answer(
            f"┌{'─' * 34}┐\n"
            f"│   ❌  <b>Fayl Hajmi Oshib Ketdi</b>        │\n"
            f"└{'─' * 34}┘\n\n"
            f"📄  <b>Fayl:</b>    <code>{file_name}</code>\n"
            f"📦  <b>Hajmi:</b>   <b>{_size_str(file_size)}</b>\n"
            f"📏  <b>Limit:</b>   <b>32 MB</b>\n\n"
            f"Iltimos, <b>32 MB</b>dan kichik fayl yuboring."
        )
        return

    # ── Boshlang'ich status ────────────────────────────
    status_msg = await message.answer(
        _status(
            file_name,
            "🔄  <b>1/4</b> — Fayl yuklab olinmoqda…",
            f"Hajm: {_size_str(file_size)}"
        )
    )

    # Windows'da fayl nomi 260 belgidan oshmasligi uchun qisqartirish
    short_id  = document.file_id[-8:]
    safe_name = file_name[-40:] if len(file_name) > 40 else file_name
    temp_file = TEMP_DIR / f"{short_id}_{safe_name}"
    try:
        # 1 — Yuklab olish
        tg_file = await bot.get_file(document.file_id)
        await bot.download_file(tg_file.file_path, destination=temp_file)

        # 2 — SHA-256
        await status_msg.edit_text(
            _status(file_name, "🔢  <b>2/4</b> — SHA-256 hash hisoblanmoqda…")
        )
        sha256 = await compute_sha256(temp_file)

        async with aiohttp.ClientSession() as session:
            # 3 — Bazadan qidirish
            await status_msg.edit_text(
                _status(
                    file_name,
                    "🔍  <b>3/4</b> — VirusTotal bazasida qidirilmoqda…",
                    f"Hash: {sha256[:12]}…{sha256[-6:]}"
                )
            )
            hash_result = await check_hash(sha256, session)

            if hash_result and "data" in hash_result:
                stats = hash_result["data"]["attributes"]["last_analysis_stats"]
                await status_msg.edit_text(
                    format_result(file_name, sha256, stats, "📚 Baza (oldin tekshirilgan)")
                )
                return

            # 4 — Yangi yuklash
            await status_msg.edit_text(
                _status(
                    file_name,
                    "📤  <b>4/4</b> — VirusTotal'ga yuklanmoqda…",
                    "70+ antivirus tekshiradi • 1–3 daqiqa davom etadi"
                )
            )
            analysis_id = await upload_file(temp_file, session)

            if not analysis_id:
                await status_msg.edit_text(
                    f"┌{'─' * 34}┐\n"
                    f"│   ❌  <b>Yuklash Muvaffaqiyatsiz</b>       │\n"
                    f"└{'─' * 34}┘\n\n"
                    f"📄  <code>{file_name}</code>\n\n"
                    f"VirusTotal'ga fayl yuklab bo'lmadi.\n"
                    f"Iltimos, biroz kutib qayta urinib ko'ring.\n\n"
                    f"💡  <i>Sabab: API cheklovi yoki server xatosi.</i>"
                )
                return

            # 5 — Polling
            await status_msg.edit_text(
                _status(
                    file_name,
                    "🔬  <b>Tahlil jarayoni</b> — 70+ antivirus tekshirmoqda…",
                    "Natijani kutmoqdamiz. Odatda 1–3 daqiqa ketadi ⏳"
                )
            )
            analysis_result = await poll_analysis(analysis_id, session)

            if not analysis_result:
                await status_msg.edit_text(
                    f"┌{'─' * 34}┐\n"
                    f"│   ⏰  <b>Tahlil Vaqti Tugadi</b>           │\n"
                    f"└{'─' * 34}┘\n\n"
                    f"📄  <code>{file_name}</code>\n\n"
                    f"Tahlil juda uzoq davom etmoqda.\n"
                    f"Bir necha daqiqadan so'ng qayta yuboring."
                )
                return

            stats = analysis_result["data"]["attributes"]["stats"]
            await status_msg.edit_text(
                format_result(file_name, sha256, stats, "🆕 Yangi tahlil (hozirgina tekshirildi)")
            )

    except Exception as e:
        logger.error(f"❌  {file_name} — {e}", exc_info=True)
        try:
            await status_msg.edit_text(
                f"┌{'─' * 34}┐\n"
                f"│   ❌  <b>Kutilmagan Xatolik</b>            │\n"
                f"└{'─' * 34}┘\n\n"
                f"📄  <code>{file_name}</code>\n\n"
                f"Texnik muammo yuz berdi.\n"
                f"Iltimos, qayta urinib ko'ring.\n\n"
                f"💡  <i>Muammo davom etsa /start yuboring.</i>"
            )
        except Exception:
            pass
    finally:
        try:
            if temp_file.exists():
                temp_file.unlink()
        except Exception as e:
            logger.warning(f"⚠️  O'chirib bo'lmadi: {e}")


@router.message(F.photo | F.video | F.voice | F.video_note | F.sticker)
async def handle_media(message: Message):
    await message.answer(
        f"┌{'─' * 34}┐\n"
        f"│   ℹ️  <b>Media Fayllar Tekshirilmaydi</b>  │\n"
        f"└{'─' * 34}┘\n\n"
        f"Rasm, video, ovoz xabarlari va stikerlar\n"
        f"odatda virus tashimaydi.\n\n"
        f"📎  Faylni tekshirish uchun:\n"
        f"  <b>Fayl sifatida</b> yuboring:\n"
        f"  📎 → Fayl → Faylni tanlang"
    )


@router.message()
async def handle_text(message: Message):
    await message.answer(
        f"┌{'─' * 34}┐\n"
        f"│   📎  <b>Fayl Yuboring</b>                 │\n"
        f"└{'─' * 34}┘\n\n"
        f"Faylni <b>hujjat sifatida</b> yuboring —\n"
        f"men uni <b>70+ antivirus</b> bilan tekshiraman.\n\n"
        f"💡  /help — Batafsil yordam"
    )


# ═══════════════════════════════════════════════════════
#  🚀  ISHGA TUSHIRISH
# ═══════════════════════════════════════════════════════

async def main():
    logger.info("🔐  SecureCheck Bot ishga tushmoqda…")
    logger.info(f"📁  Temp: {TEMP_DIR}")
    for f in TEMP_DIR.iterdir():
        try:
            f.unlink()
        except Exception:
            pass
    await dp.start_polling(bot)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("🛑  Bot to'xtatildi.")