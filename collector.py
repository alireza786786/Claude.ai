#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🚀 V2Ray Smart Collector v2.2 — Production Edition (Fixed + Reliable Rename)
اجرا در Termux، GitHub Actions، یا هر محیط Python 3.10+

تغییرات نسبت به v2.0:
  - پارس درست میزبان/پورت برای vmess:// و ss:// (باگ قبلی: هر دو همیشه رد می‌شدند)
  - GeoIP به‌صورت async و موازی + کش persistent در دیتابیس (قبلاً سریالی و in-memory بود)
  - خطاها به‌جای بلعیده‌شدن، در سطح debug لاگ می‌شوند
  - dedup بر اساس host:port قبل از تست (نه فقط رشته‌ی کامل کانفیگ)
  - اعتبارسنجی host با idna/ipaddress به‌جای replace/isalnum دستی
  - تفکیک تست Reality (CERT_NONE منطقی است) از تست TLS معمولی

تغییرات v2.2:
  - CFG.INCLUDE_VMESS (پیش‌فرض False): vmess اصلاً استخراج/تست نمی‌شود.
  - rename تضمینی و پروتکل‌آگاه: برای vmess فیلد JSON "ps" مستقیماً بازنویسی
    می‌شود (نه فقط فرگمنت #)، چون کلاینت‌ها نام را از همان‌جا می‌خوانند.
    برای vless/trojan/hysteria2/ss هم فرگمنت قبلی کامل با نام کانال جایگزین
    می‌شود (نه append) تا هیچ نام قدیمی باقی نماند.
"""

import os
import sys
import time
import socket
import ssl
import random
import asyncio
import base64
import gzip
import zlib
import json
import ipaddress
import sqlite3
import logging
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, unquote, quote, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
import zipfile

try:
    import aiohttp
except ImportError:
    os.system(f"{sys.executable} -m pip install aiohttp -q")
    import aiohttp

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


# =============================================================================
# تنظیمات
# =============================================================================

@dataclass(frozen=True)
class Config:
    BOT_TOKEN: str = field(default_factory=lambda: os.environ.get("BOT_TOKEN", ""))
    CHAT_ID: str = field(default_factory=lambda: os.environ.get("CHAT_ID", ""))
    MY_CHANNEL_ID: str = "Goodbaye_filtering"
    TELEGRAM_LINK: str = "https://t.me/Goodbaye_filtering"
    CHAT_GROUP_LINK: str = "https://t.me/CONFIG_V2RAY_VIP"

    SOURCES: tuple = (
        "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/vless.txt",
        "https://manager.onetwothree123.ir/",
        "https://raw.githubusercontent.com/IranianScanner/V2RayAggregator/master/sub/sub_merge.txt",
        "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",
        "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/main/category/vless.txt",
        "https://raw.githubusercontent.com/SoliSpirit/SolVPN/main/Protocols/vless.txt",
        "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no1.txt",
        "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no2.txt",
        "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no3.txt",
        "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no4.txt",
        "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no5.txt",
        "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no6.txt",
        "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no7.txt",
        "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no8.txt",
        "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no9.txt",
        "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no10.txt",
        "https://raw.githubusercontent.com/Q3dlaXpoaQ/Q3dlaXpoaQ.github.io/main/APIs/cg1.txt",
        "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/main/mci/sub_1.txt",
        "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/main/mtn/sub_1.txt",
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
        "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/ir/vless.txt",
        "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/hysteria2",
    )

    MAX_WORKERS: int = 50
    GEO_MAX_CONCURRENT: int = 20
    GEO_TIMEOUT: float = 3.0
    GEO_MAX_CALLS_PER_RUN: int = 800
    TCP_TIMEOUT: float = 1.5
    TLS_TIMEOUT: float = 2.5
    MAX_PING_MS: int = 400
    MAX_TLS_PING_MS: int = 600
    MAX_CANDIDATES: int = 1500
    TOP_N_FINAL: int = 500
    CHUNK_SIZE: int = 150
    STABILITY_ROUNDS: int = 2

    # --- تست واقعی اتصال (v2.3): به‌جای فقط چک کردن باز بودن پورت، یک پروکسی
    # واقعی Xray بالا می‌آید و یک درخواست اینترنتی واقعی از آن رد می‌شود.
    # اگر باینری Xray در دسترس نباشد یا خطای زیرساختی رخ دهد، این مرحله به‌طور
    # خودکار نادیده گرفته می‌شود و رفتار قبلی (بدون تست واقعی) ادامه پیدا می‌کند.
    REAL_TEST_ENABLED: bool = True
    REAL_TEST_MAX_CANDIDATES: int = 250
    REAL_TEST_CONCURRENCY: int = 15
    REAL_TEST_URL: str = "http://cp.cloudflare.com/generate_204"
    REAL_TEST_TIMEOUT: float = 5.0

    # vmess عمداً حذف شد: نام کانال داخل JSON پنهان (فیلد "ps") است و با فرگمنت
    # ساده قابل بازنویسی تضمینی نبود. اگر بعداً خواستی روشنش کنی:
    # INCLUDE_VMESS=True کن؛ rename برای vmess حالا به‌صورت واقعی روی JSON کار می‌کند.
    INCLUDE_VMESS: bool = False

    BASE_SCHEMES: tuple = (
        "vless://", "ss://",
        "hysteria2://", "hy2://", "trojan://"
    )

    # نام ثابتی که باید جایگزین نام تمام کانفیگ‌ها (بدون استثنا) شود
    CHANNEL_TAG: str = "Goodbaye_filtering"

    DB_PATH: str = "history.db"
    OUTPUT_DIR: str = "."

    @property
    def ALLOWED_SCHEMES(self) -> tuple:
        return self.BASE_SCHEMES + (("vmess://",) if self.INCLUDE_VMESS else ())


CFG = Config()


def setup_logging():
    logger = logging.getLogger("v2ray")
    logger.setLevel(logging.DEBUG)
    if logger.handlers:
        return logger
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"
    ))
    logger.addHandler(handler)
    return logger


log = setup_logging()


# =============================================================================
# مدل‌های داده
# =============================================================================

@dataclass
class ParsedConfig:
    """نتیجه‌ی پارس یک لینک کانفیگ، مستقل از پروتکل."""
    raw: str
    scheme: str
    host: str
    port: int
    remark: str = ""


@dataclass
class TestResult:
    config: str
    host: str
    port: int
    tcp_ping: Optional[int] = None
    tls_ping: Optional[int] = None
    handshake_ok: bool = False
    is_reality: bool = False
    is_hysteria2: bool = False
    is_trojan: bool = False
    is_vless: bool = False
    is_vmess: bool = False
    is_ss: bool = False
    scheme: str = ""
    stability: float = 0.0


@dataclass
class ScoredNode:
    score: float
    config: str
    name: str
    ping: int
    country: str
    city: str
    flag: str
    protocol: str
    host: str
    port: int
    scheme: str = ""
    speed_mbps: float = 0.0


# =============================================================================
# پارسر کانفیگ (اصلاح اصلی)
# =============================================================================

class ConfigParser:
    """
    استخراج host/port برای هر ۶ پروتکل.
    vless/trojan/hysteria2/hy2 => فرمت URL استاندارد است، urlparse کافیست.
    vmess://  => base64(JSON) ; باید دیکد و از فیلد add/port خوانده شود.
    ss://     => base64(method:password)@host:port#name  یا کل‌بخش base64
    """

    @staticmethod
    def parse(conf: str) -> Optional[ParsedConfig]:
        try:
            if conf.startswith("vmess://"):
                return ConfigParser._parse_vmess(conf)
            if conf.startswith("ss://"):
                return ConfigParser._parse_ss(conf)
            # vless / trojan / hysteria2 / hy2 -> URL استاندارد
            p = urlparse(conf)
            if not p.hostname or not p.port:
                return None
            return ParsedConfig(
                raw=conf, scheme=p.scheme, host=p.hostname, port=p.port,
                remark=unquote(p.fragment or ""),
            )
        except Exception as e:
            log.debug(f"parse fail ({conf[:30]}...): {e}")
            return None

    @staticmethod
    def _parse_vmess(conf: str) -> Optional[ParsedConfig]:
        body = conf[len("vmess://"):]
        pad = "=" * (-len(body) % 4)
        try:
            data = base64.b64decode(body + pad, validate=False)
            obj = json.loads(data.decode("utf-8", errors="ignore"))
        except Exception as e:
            log.debug(f"vmess decode fail: {e}")
            return None
        host = obj.get("add")
        port = obj.get("port")
        if not host or not port:
            return None
        try:
            port = int(port)
        except (TypeError, ValueError):
            return None
        return ParsedConfig(raw=conf, scheme="vmess", host=host, port=port,
                             remark=str(obj.get("ps", "")))

    @staticmethod
    def _parse_ss(conf: str) -> Optional[ParsedConfig]:
        body = conf[len("ss://"):]
        remark = ""
        if "#" in body:
            body, frag = body.split("#", 1)
            remark = unquote(frag)

        # حالت جدید: ss://base64(method:pass)@host:port
        if "@" in body:
            userinfo, hostport = body.rsplit("@", 1)
            try:
                pad = "=" * (-len(userinfo) % 4)
                base64.b64decode(userinfo + pad)  # فقط اعتبارسنجی
            except Exception:
                pass  # ممکن است userinfo از قبل plain باشد
            if ":" not in hostport:
                return None
            host, _, port_s = hostport.rpartition(":")
            try:
                port = int(port_s)
            except ValueError:
                return None
            return ParsedConfig(raw=conf, scheme="ss", host=host, port=port, remark=remark)

        # حالت قدیمی: کل بخش base64(method:pass@host:port)
        pad = "=" * (-len(body) % 4)
        try:
            decoded = base64.b64decode(body + pad).decode("utf-8", errors="ignore")
            if "@" not in decoded or ":" not in decoded:
                return None
            _, hostport = decoded.rsplit("@", 1)
            host, _, port_s = hostport.rpartition(":")
            port = int(port_s)
            return ParsedConfig(raw=conf, scheme="ss", host=host, port=port, remark=remark)
        except Exception as e:
            log.debug(f"ss decode fail: {e}")
            return None

    @staticmethod
    def rename(raw: str, scheme: str, new_name: str) -> str:
        """
        بازنویسی تضمینی نام روی لینک نهایی، مخصوص هر پروتکل:
          - vmess: نام واقعاً داخل فیلد JSON "ps" بازنویسی می‌شود (تنها جایی که
            کلاینت‌ها نام را از آن می‌خوانند). فرگمنت اضافه‌شده بی‌اثر است.
          - vless/trojan/hysteria2/hy2/ss: هر فرگمنت قبلی (نام قدیمی) کامل حذف و
            نام جدید جایگزین می‌شود؛ نام قدیمی جایی باقی نمی‌ماند.
        در هر دو حالت خروجی تضمین می‌کند که نام قبلی دیگر در لینک دیده نشود.
        """
        if scheme == "vmess":
            return ConfigParser._rename_vmess(raw, new_name)
        base = raw.split("#", 1)[0]
        return f"{base}#{quote(new_name)}"

    @staticmethod
    def _rename_vmess(raw: str, new_name: str) -> str:
        body = raw[len("vmess://"):].split("#", 1)[0]
        pad = "=" * (-len(body) % 4)
        try:
            data = base64.b64decode(body + pad, validate=False)
            obj = json.loads(data.decode("utf-8", errors="ignore"))
        except Exception as e:
            log.debug(f"rename vmess failed, cannot edit JSON: {e}")
            # اگر JSON قابل دیکد نبود، این کانفیگ اصلاً قابل rename تضمینی نیست
            # و بهتر است حذف شود تا نام قدیمی به اشتباه منتشر نشود.
            return ""
        obj["ps"] = new_name
        new_body = base64.b64encode(
            json.dumps(obj, ensure_ascii=False).encode("utf-8")
        ).decode()
        return f"vmess://{new_body}"

    @staticmethod
    def is_valid_host(host: str) -> bool:
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            pass
        try:
            host.encode("idna")
            return True
        except Exception:
            return False


# =============================================================================
# دیتابیس (تاریخچه عملکرد + کش Geo persistent)
# =============================================================================

class HistoryDB:
    def __init__(self, path: str = CFG.DB_PATH):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS node_history (
                host TEXT NOT NULL, port INTEGER NOT NULL,
                last_ping INTEGER, last_score REAL,
                success_count INTEGER DEFAULT 0, fail_count INTEGER DEFAULT 0,
                last_seen TEXT, PRIMARY KEY (host, port)
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS geo_cache (
                host TEXT PRIMARY KEY, flag TEXT, cc TEXT,
                country TEXT, city TEXT, cached_at TEXT
            )
        """)
        # پاک‌سازی یک‌باره‌ی نتایج قدیمی «Unknown» (از سرویس جغرافیایی قبلی) تا با
        # سرویس جدید دوباره تلاش شود، بدون اینکه بقیه‌ی تاریخچه/امتیازها پاک شود.
        self.conn.execute("DELETE FROM geo_cache WHERE country = 'Unknown' OR cc = 'XX'")
        self.conn.commit()

    def record(self, host: str, port: int, ping: int, score: float, success: bool):
        now = datetime.now(timezone.utc).isoformat()
        try:
            if success:
                self.conn.execute("""
                    INSERT INTO node_history (host, port, last_ping, last_score, success_count, last_seen)
                    VALUES (?, ?, ?, ?, 1, ?)
                    ON CONFLICT(host, port) DO UPDATE SET
                        last_ping=excluded.last_ping, last_score=excluded.last_score,
                        success_count=success_count+1, last_seen=excluded.last_seen
                """, (host, port, ping, score, now))
            else:
                self.conn.execute("""
                    INSERT INTO node_history (host, port, fail_count, last_seen)
                    VALUES (?, ?, 1, ?)
                    ON CONFLICT(host, port) DO UPDATE SET
                        fail_count=fail_count+1, last_seen=excluded.last_seen
                """, (host, port, now))
            self.conn.commit()
        except Exception as e:
            log.warning(f"DB record error: {e}")

    def get_reliability_bonus(self, host: str, port: int) -> float:
        try:
            cur = self.conn.execute(
                "SELECT success_count, fail_count FROM node_history WHERE host=? AND port=?",
                (host, port))
            row = cur.fetchone()
            if not row:
                return 0.0
            success, fail = row
            if success + fail < 3:
                return 0.0
            ratio = success / (success + fail)
            return (ratio - 0.5) * 200
        except Exception as e:
            log.debug(f"reliability lookup fail: {e}")
            return 0.0

    def get_geo_cached(self, host: str) -> Optional[Tuple[str, str, str, str]]:
        try:
            cur = self.conn.execute(
                "SELECT flag, cc, country, city FROM geo_cache WHERE host=?", (host,))
            row = cur.fetchone()
            return tuple(row) if row else None
        except Exception:
            return None

    def set_geo_cached(self, host: str, flag: str, cc: str, country: str, city: str):
        try:
            self.conn.execute("""
                INSERT INTO geo_cache (host, flag, cc, country, city, cached_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(host) DO UPDATE SET
                    flag=excluded.flag, cc=excluded.cc,
                    country=excluded.country, city=excluded.city, cached_at=excluded.cached_at
            """, (host, flag, cc, country, city, datetime.now(timezone.utc).isoformat()))
            self.conn.commit()
        except Exception as e:
            log.debug(f"geo cache write fail: {e}")

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass


# =============================================================================
# دریافت Async منابع
# =============================================================================

class AsyncFetcher:
    def __init__(self, max_concurrent: int = 30):
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.timeout = aiohttp.ClientTimeout(total=15, connect=5)

    async def fetch_one(self, session: aiohttp.ClientSession, url: str) -> str:
        async with self.semaphore:
            for attempt in range(2):
                try:
                    async with session.get(
                        url, timeout=self.timeout,
                        headers={"User-Agent": "V2RayCollector/2.1"}
                    ) as r:
                        if r.status == 200:
                            return await r.text()
                        log.debug(f"fetch {url} -> status {r.status}")
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    log.debug(f"fetch {url} attempt {attempt}: {e}")
                    if attempt == 0:
                        await asyncio.sleep(0.5)
            return ""

    async def fetch_all(self, urls: List[str]) -> List[str]:
        connector = aiohttp.TCPConnector(limit=50, ttl_dns_cache=300)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self.fetch_one(session, u) for u in urls]
            return await asyncio.gather(*tasks)


class ConfigDecoder:
    """رمزگشایی سطح فایل منبع (کل sub ممکن است base64/gzip باشد)."""

    @staticmethod
    def try_b64(text: str) -> Optional[str]:
        try:
            clean = text.replace('\n', '').replace('\r', '').replace(' ', '')
            if len(clean) < 16:
                return None
            pad = '=' * (-len(clean) % 4)
            decoded = base64.b64decode(clean + pad, validate=True)
            txt = decoded.decode('utf-8', errors='ignore')
            return txt if any(p in txt for p in CFG.ALLOWED_SCHEMES) else None
        except Exception:
            return None

    @classmethod
    def decode_all(cls, raw: str) -> List[str]:
        results = {raw}
        b64 = cls.try_b64(raw)
        if b64:
            results.add(b64)
            b64_n = cls.try_b64(b64)
            if b64_n:
                results.add(b64_n)
        try:
            data = raw.encode()
            for fn in (gzip.decompress, zlib.decompress):
                try:
                    t = fn(data).decode('utf-8', errors='ignore')
                    if "://" in t:
                        results.add(t)
                except Exception:
                    pass
        except Exception:
            pass
        return list(results)


# =============================================================================
# تست شبکه
# =============================================================================

# =============================================================================
# حفاظت SSRF — قبل از وصل شدن به هر میزبان، مطمئن می‌شویم آی‌پی واقعی‌اش
# داخلی/خصوصی/متادیتای ابری نیست (مثلاً 127.0.0.1 یا آدرس متادیتای آژور
# که گیت‌هاب اکشنز رویش اجرا می‌شود). این از سوءاستفاده‌ی یک کانفیگ مخرب
# برای اسکن یا دسترسی به شبکه‌ی داخلی جلوگیری می‌کند.
# =============================================================================

def _is_public_ip(ip_obj) -> bool:
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
        return False
    if ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
        return False
    if isinstance(ip_obj, ipaddress.IPv4Address):
        # فضای CGNAT (100.64.0.0/10) هم داخلی محسوب می‌شود
        if ip_obj in ipaddress.ip_network("100.64.0.0/10"):
            return False
    return True


def resolve_safe_ip(host: str) -> Optional[str]:
    """میزبان را به آی‌پی واقعی تبدیل می‌کند و فقط اگر آی‌پی عمومی بود
    برش می‌گرداند؛ در غیر این صورت None (یعنی این کاندید رد می‌شود)."""
    try:
        try:
            ip_obj = ipaddress.ip_address(host)
            return host if _is_public_ip(ip_obj) else None
        except ValueError:
            pass
        infos = socket.getaddrinfo(host, None)
        for info in infos:
            ip_str = info[4][0]
            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            if _is_public_ip(ip_obj):
                return ip_str
        return None
    except Exception:
        return None


class AdvancedTester:
    def __init__(self, max_workers: int = None):
        self.max_workers = max_workers or CFG.MAX_WORKERS

    @staticmethod
    def tcp_ping(host: str, port: int, timeout: float) -> Optional[int]:
        safe_ip = resolve_safe_ip(host)
        if safe_ip is None:
            return None
        try:
            start = time.perf_counter()
            with socket.create_connection((safe_ip, port), timeout=timeout):
                return int((time.perf_counter() - start) * 1000)
        except Exception:
            return None

    @staticmethod
    def tls_handshake(host: str, port: int, timeout: float,
                       allow_self_signed: bool) -> Tuple[bool, Optional[int]]:
        safe_ip = resolve_safe_ip(host)
        if safe_ip is None:
            return False, None
        try:
            start = time.perf_counter()
            ctx = ssl.create_default_context()
            if allow_self_signed:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            with socket.create_connection((safe_ip, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    ss.do_handshake()
                    if not ss.cipher():
                        return False, None
            return True, int((time.perf_counter() - start) * 1000)
        except Exception:
            return False, None

    def test_single(self, pc: ParsedConfig) -> Optional[TestResult]:
        try:
            if not ConfigParser.is_valid_host(pc.host):
                return None

            upper = pc.raw.upper()
            is_reality = "REALITY" in upper
            is_hy2 = pc.scheme in ("hysteria2", "hy2")
            is_trojan = pc.scheme == "trojan"
            is_vless = pc.scheme == "vless"
            is_vmess = pc.scheme == "vmess"
            is_ss = pc.scheme == "ss"
            needs_tls = pc.scheme in ("vless", "trojan", "hysteria2", "hy2")

            tcp = self.tcp_ping(pc.host, pc.port, CFG.TCP_TIMEOUT)
            if tcp is None or tcp > CFG.MAX_PING_MS:
                return None

            result = TestResult(
                config=pc.raw, host=pc.host, port=pc.port, tcp_ping=tcp,
                is_reality=is_reality, is_hysteria2=is_hy2, is_trojan=is_trojan,
                is_vless=is_vless, is_vmess=is_vmess, is_ss=is_ss, scheme=pc.scheme,
            )

            if needs_tls and not is_reality:
                ok, tls_p = self.tls_handshake(pc.host, pc.port, CFG.TLS_TIMEOUT,
                                                allow_self_signed=False)
                result.handshake_ok = ok
                result.tls_ping = tls_p
                if not ok or (tls_p and tls_p > CFG.MAX_TLS_PING_MS):
                    return None

            if is_reality:
                ok, tls_p = self.tls_handshake(pc.host, pc.port, CFG.TLS_TIMEOUT,
                                                allow_self_signed=True)
                if not ok:
                    return None
                result.handshake_ok = ok
                result.tls_ping = tls_p

            pings = [tcp]
            for _ in range(CFG.STABILITY_ROUNDS - 1):
                p = self.tcp_ping(pc.host, pc.port, CFG.TCP_TIMEOUT)
                if p:
                    pings.append(p)
                else:
                    return None
            result.tcp_ping = min(pings)
            result.stability = 1.0 - (max(pings) - min(pings)) / max(max(pings), 1)
            return result
        except Exception as e:
            log.debug(f"test_single fail {pc.host}:{pc.port}: {e}")
            return None

    def test_all(self, parsed: List[ParsedConfig]) -> List[TestResult]:
        log.info(f"🔬 تست شبکه روی {len(parsed)} کانفیگ...")
        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {ex.submit(self.test_single, p): p for p in parsed}
            done = 0
            for fut in as_completed(futures):
                done += 1
                if done % 200 == 0:
                    log.info(f"   پیشرفت: {done}/{len(parsed)} | قبول: {len(results)}")
                r = fut.result()
                if r:
                    results.append(r)
        log.info(f"✅ {len(results)} کانفیگ سالم از {len(parsed)}")
        return results


# =============================================================================
# جغرافیا (async + کش persistent)
# =============================================================================

class GeoLocator:
    BATCH_URL = "http://ip-api.com/batch?fields=status,country,countryCode,city,query"
    BATCH_SIZE = 100
    BATCH_SLEEP = 1.5  # محدودیت رایگان ip-api.com: ۴۵ درخواست در دقیقه

    def __init__(self, db: HistoryDB, max_concurrent: int = CFG.GEO_MAX_CONCURRENT):
        self.db = db
        self.api_calls = 0  # تعداد درخواست‌های دسته‌ای (نه تعداد میزبان‌ها)

    @staticmethod
    def _flag(cc: str) -> str:
        try:
            return ''.join(chr(127397 + ord(c)) for c in cc.upper()[:2] if c.isalpha())
        except Exception:
            return "🌐"

    async def resolve_all(self, hosts: List[str]) -> dict:
        """host -> (flag, cc, country, city) برای همه؛ با یک درخواست دسته‌ای
        به‌جای هزاران درخواست تکی — سریع‌تر و دوستانه‌تر با محدودیت نرخ."""
        unique_hosts = list(dict.fromkeys(hosts))
        default = ("🌐", "XX", "Unknown", "Server")
        result: dict = {}
        to_fetch: List[str] = []

        for h in unique_hosts:
            cached = self.db.get_geo_cached(h)
            if cached:
                result[h] = cached
            else:
                to_fetch.append(h)

        if not to_fetch:
            return result

        async with aiohttp.ClientSession() as session:
            for i in range(0, len(to_fetch), self.BATCH_SIZE):
                if self.api_calls >= CFG.GEO_MAX_CALLS_PER_RUN:
                    break
                chunk = to_fetch[i:i + self.BATCH_SIZE]
                self.api_calls += 1
                try:
                    async with session.post(
                        self.BATCH_URL, json=chunk,
                        timeout=aiohttp.ClientTimeout(total=CFG.GEO_TIMEOUT * 3),
                        headers={"User-Agent": "V2RayCollector/2.2"},
                    ) as r:
                        rows = await r.json(content_type=None)
                except Exception as e:
                    log.debug(f"geo batch lookup fail: {e}")
                    rows = []

                for item in (rows or []):
                    host = item.get("query", "")
                    if not host:
                        continue
                    if item.get("status") != "success":
                        result[host] = default
                        continue
                    cc = item.get("countryCode", "XX") or "XX"
                    country = item.get("country", "Unknown") or "Unknown"
                    city = item.get("city") or "Server"
                    flag = self._flag(cc)
                    self.db.set_geo_cached(host, flag, cc, country, city)
                    result[host] = (flag, cc, country, city)

                if i + self.BATCH_SIZE < len(to_fetch):
                    await asyncio.sleep(self.BATCH_SLEEP)

        for h in to_fetch:
            if h not in result:
                result[h] = default
        return result


# =============================================================================
# امتیازدهی
# =============================================================================

class SmartScorer:
    PROTO_BONUS = {
        "REALITY": 600, "HYSTERIA2": 500, "TROJAN": 350,
        "VLESS": 200, "VMESS": 180, "SS": 100,
    }
    COUNTRY_BONUS = {
        "IR": 300, "TR": 250, "AE": 230, "AZ": 220, "AM": 200,
        "IQ": 210, "TM": 200, "GE": 190, "RU": 150, "OM": 180,
        "DE": 80, "NL": 70, "FI": 60, "FR": 50, "GB": 40,
        "IT": 30, "PL": 30, "CA": 20, "US": 10,
    }
    # پورت‌های طلایی برای عبور بهتر از فیلترینگ ایران: پورت ۴۴۳ (همان پورت
    # استاندارد HTTPS) بالاترین اولویت را دارد، بعد ۸۴۴۳، بعد پورت‌های
    # رایج CDNهایی مثل کلادفلر که مسدودکردن‌شان یعنی مسدود کردن بخش بزرگی
    # از اینترنت برای همه.
    GOLDEN_PORTS = {
        443: 250,
        8443: 150,
        2053: 100, 2083: 100, 2087: 100, 2096: 100,
        80: 60, 8080: 60, 8880: 60, 2052: 60, 2082: 60, 2086: 60,
    }

    def __init__(self, db: HistoryDB, geo_map: dict):
        self.db = db
        self.geo_map = geo_map  # host -> (flag, cc, country, city)

    def score_one(self, r: TestResult) -> Optional[ScoredNode]:
        try:
            ping = r.tls_ping or r.tcp_ping
            if not ping:
                return None
            score = 1000 - ping

            if r.is_reality:
                score += self.PROTO_BONUS["REALITY"]; protocol = "Reality"
            elif r.is_hysteria2:
                score += self.PROTO_BONUS["HYSTERIA2"]; protocol = "Hysteria2"
            elif r.is_trojan:
                score += self.PROTO_BONUS["TROJAN"]; protocol = "Trojan"
            elif r.is_vless:
                score += self.PROTO_BONUS["VLESS"]; protocol = "Vless"
            elif r.is_vmess:
                score += self.PROTO_BONUS["VMESS"]; protocol = "Vmess"
            elif r.is_ss:
                score += self.PROTO_BONUS["SS"]; protocol = "SS"
            else:
                score += self.PROTO_BONUS["SS"]; protocol = "Unknown"

            flag, cc, country, city = self.geo_map.get(r.host, ("🌐", "XX", "Unknown", "Server"))
            score += self.COUNTRY_BONUS.get(cc, 0)
            score += self.GOLDEN_PORTS.get(r.port, 0)

            if r.tls_ping and r.tls_ping > 350:
                score -= 150
            if r.handshake_ok and r.is_reality:
                score += 100
            # ترکیب VLESS+Reality+Vision طبق تحقیقات ۲۰۲۶ (greatfirewallguide.com)
            # نزدیک به ۹۸٪ نرخ عبور از فیلترینگ دارد — بالاترین امتیاز اضافه را می‌گیرد
            if r.is_reality and "flow=xtls-rprx-vision" in r.config:
                score += 150

            # سه ترکیب پرکاربرد و پراعتمادی که کاربر بر اساس تجربه‌ی واقعی
            # مشخص کرده: هرکدام علاوه بر بونوس‌های بالا، امتیاز ترکیبی
            # جداگانه هم می‌گیرند تا در رده‌بندی نهایی جلوتر بیفتند.
            config_upper = r.config.upper()
            is_grpc = "TYPE=GRPC" in config_upper
            is_tls_plain = "SECURITY=TLS" in config_upper  # TLS معمولی، نه Reality
            if r.is_vless and r.is_reality and is_grpc:
                score += 200  # ⚡️ VLESS + gRPC + Reality
            elif r.is_vless and is_tls_plain:
                score += 150  # VLESS + TLS
            elif r.is_vless and r.is_reality:
                score += 100  # VLESS + Reality (سایر ترنسپورت‌ها)

            score += r.stability * 50
            score += self.db.get_reliability_bonus(r.host, r.port)

            name = f"👉🆔@{CFG.CHANNEL_TAG}📡{flag}®️{country}©️{city}"
            final_link = ConfigParser.rename(r.config, r.scheme, name)
            if not final_link:
                # rename تضمینی ممکن نبود (مثلاً JSON خراب) -> این کانفیگ منتشر نشود
                return None
            return ScoredNode(
                score=score, config=final_link, name=name, ping=ping,
                country=country, city=city, flag=flag, protocol=protocol,
                host=r.host, port=r.port, scheme=r.scheme,
            )
        except Exception as e:
            log.debug(f"score_one fail {r.host}: {e}")
            return None

    def score_all(self, results: List[TestResult]) -> List[ScoredNode]:
        scored = [s for s in (self.score_one(r) for r in results) if s]
        scored.sort(key=lambda x: x.score, reverse=True)
        return scored


# =============================================================================
# ارسال تلگرام
# =============================================================================

class TelegramSender:
    def __init__(self):
        self.base = f"https://api.telegram.org/bot{CFG.BOT_TOKEN}"
        self.semaphore = asyncio.Semaphore(3)

    async def _send_one(self, session: aiohttp.ClientSession,
                         file_path: str, caption: str, num: int) -> bool:
        async with self.semaphore:
            for attempt in range(3):
                try:
                    data = aiohttp.FormData()
                    data.add_field('chat_id', CFG.CHAT_ID)
                    data.add_field('caption', caption)
                    with open(file_path, 'rb') as f:
                        data.add_field('document', f, filename=file_path)
                        async with session.post(
                            f"{self.base}/sendDocument", data=data,
                            timeout=aiohttp.ClientTimeout(total=60)
                        ) as resp:
                            r = await resp.json()
                    if r.get("ok"):
                        log.info(f"   ✅ پارت {num} ارسال شد")
                        return True
                    log.warning(f"   ⚠️ خطا: {r.get('description')}")
                    retry_after = r.get("parameters", {}).get("retry_after")
                    if retry_after:
                        await asyncio.sleep(retry_after)
                except Exception as e:
                    log.error(f"   ❌ Attempt {attempt+1}: {e}")
                    await asyncio.sleep(2 ** attempt)
        return False

    def build(self, nodes: List[ScoredNode]) -> List[Tuple[str, str]]:
        parts = []
        for i in range(0, len(nodes), CFG.CHUNK_SIZE):
            n = (i // CFG.CHUNK_SIZE) + 1
            chunk = nodes[i:i + CFG.CHUNK_SIZE]
            fname = f"subscription_part{n}.txt"
            header = (
                f"# 🔥 اشتراک هوشمند V2Ray v2.1\n"
                f"# 📦 فایل: {fname}\n"
                f"# 📊 تعداد: {len(chunk)} کانفیگ تست‌شده\n"
                f"# ⏰ زمان: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"# ✨ {CFG.TELEGRAM_LINK}\n"
                f"# {'='*50}\n"
            )
            with open(fname, "w", encoding="utf-8") as f:
                # x.config از قبل با ConfigParser.rename ساخته شده و نام کانال را
                # برای هر پروتکل به روش تضمینی آن (JSON برای vmess، فرگمنت برای بقیه)
                # در خودش دارد؛ اینجا نباید دوباره #name اضافه شود.
                f.write(header + "\n".join(x.config for x in chunk))
            caption = (
                f"🔥 *اشتراک هوشمند - پارت {n}*\n\n"
                f"📦 فایل: `{fname}`\n"
                f"📊 تعداد: *{len(chunk)}* کانفیگ تست‌شده\n\n"
                f"💬 گروه: {CFG.CHAT_GROUP_LINK}\n"
                f"✨ کانال: {CFG.TELEGRAM_LINK}"
            )
            parts.append((fname, caption))
        return parts

    async def send_all(self, parts: List[Tuple[str, str]]):
        if not CFG.BOT_TOKEN or not CFG.CHAT_ID:
            log.warning("⚠️ BOT_TOKEN یا CHAT_ID تنظیم نشده. فقط فایل‌ها ساخته می‌شوند.")
            return
        async with aiohttp.ClientSession() as session:
            tasks = [self._send_one(session, f, c, i) for i, (f, c) in enumerate(parts, 1)]
            await asyncio.gather(*tasks)


# =============================================================================
# تست واقعی اتصال (Xray) — v2.3
# =============================================================================
# این بخش کاملاً مجزا و «ایمن در برابر خطا» است: هر خطای غیرمنتظره در این
# مرحله فقط باعث می‌شود همان کاندید (یا کل این مرحله) نادیده گرفته شود، نه
# اینکه کل فرآیند جمع‌آوری متوقف شود.

_XRAY_PORT_COUNTER = {"n": 28000}


def _next_local_port() -> int:
    _XRAY_PORT_COUNTER["n"] += 1
    return _XRAY_PORT_COUNTER["n"]


async def ensure_xray_binary() -> Optional[str]:
    """دانلود یک‌باره‌ی باینری Xray-core. در صورت هر شکستی، None برمی‌گرداند
    و تست واقعی به‌طور خودکار برای کل اجرا غیرفعال می‌شود."""
    bin_dir = os.path.join(CFG.OUTPUT_DIR, ".xray_bin")
    bin_path = os.path.join(bin_dir, "xray")
    if os.path.exists(bin_path) and os.access(bin_path, os.X_OK):
        return bin_path
    try:
        os.makedirs(bin_dir, exist_ok=True)
        url = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
        zip_path = bin_path + ".zip"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as r:
                if r.status != 200:
                    log.warning(f"⚠️ دانلود Xray ناموفق (HTTP {r.status}) — تست واقعی رد شد")
                    return None
                data = await r.read()
        with open(zip_path, "wb") as f:
            f.write(data)
        with zipfile.ZipFile(zip_path) as z:
            z.extract("xray", bin_dir)
        os.chmod(bin_path, 0o755)
        os.remove(zip_path)
        return bin_path
    except Exception as e:
        log.warning(f"⚠️ آماده‌سازی Xray ناموفق: {e} — تست واقعی رد شد")
        return None


def build_xray_outbound(raw: str, scheme: str) -> Optional[dict]:
    """ساخت outbound سازگار با Xray از روی لینک کانفیگ. فقط vless/trojan/ss
    پشتیبانی می‌شود (hysteria2 توسط Xray-core پشتیبانی نمی‌شود)."""
    try:
        p = urlparse(raw)
        qs = {k: v[0] for k, v in parse_qs(p.query).items()}
        host, port = p.hostname, p.port
        if not host or not port:
            return None

        network = qs.get("type", "tcp") or "tcp"
        security = qs.get("security", "") or ""
        sni = qs.get("sni") or qs.get("host") or host
        fp = qs.get("fp", "chrome") or "chrome"

        stream: dict = {"network": network}
        if security == "reality":
            stream["security"] = "reality"
            stream["realitySettings"] = {
                "serverName": sni, "fingerprint": fp,
                "shortId": qs.get("sid", ""), "publicKey": qs.get("pbk", ""),
                "spiderX": qs.get("spx", ""),
            }
        elif security == "tls":
            stream["security"] = "tls"
            stream["tlsSettings"] = {
                "serverName": sni, "allowInsecure": True, "fingerprint": fp,
            }

        if network == "ws":
            stream["wsSettings"] = {
                "path": qs.get("path", "/") or "/",
                "headers": {"Host": qs.get("host", sni)},
            }
        elif network == "grpc":
            stream["grpcSettings"] = {"serviceName": qs.get("serviceName", "")}

        if scheme == "vless":
            uid = unquote(p.username or "")
            return {
                "protocol": "vless",
                "settings": {"vnext": [{
                    "address": host, "port": port,
                    "users": [{
                        "id": uid,
                        "encryption": qs.get("encryption", "none") or "none",
                        "flow": qs.get("flow", "") or "",
                    }],
                }]},
                "streamSettings": stream,
            }

        if scheme == "trojan":
            password = unquote(p.username or "")
            if not stream.get("security"):
                stream["security"] = "tls"
                stream["tlsSettings"] = {"serverName": sni, "allowInsecure": True, "fingerprint": fp}
            return {
                "protocol": "trojan",
                "settings": {"servers": [{"address": host, "port": port, "password": password}]},
                "streamSettings": stream,
            }

        if scheme == "ss":
            userinfo = unquote(p.username or "")
            method, password = None, None
            try:
                pad = "=" * (-len(userinfo) % 4)
                decoded = base64.urlsafe_b64decode(userinfo + pad).decode()
                method, password = decoded.split(":", 1)
            except Exception:
                if ":" in userinfo:
                    method, password = userinfo.split(":", 1)
            if not method or not password:
                return None
            return {
                "protocol": "shadowsocks",
                "settings": {"servers": [{
                    "address": host, "port": port, "method": method, "password": password,
                }]},
            }

        return None
    except Exception as e:
        log.debug(f"build_xray_outbound fail: {e}")
        return None


async def real_test_one(xray_path: str, raw_config: str, scheme: str) -> Tuple[bool, float]:
    """اجرای واقعی یک پروکسی، رد کردن یک درخواست اینترنتی، و در صورت موفقیت
    اندازه‌گیری سرعت دانلود واقعی (Mbps) از همان اتصال.
    (ok=True, speed_mbps) یعنی «واقعاً کار می‌کند»؛ ok=False یعنی «رد شود».
    هر خطای زیرساختیِ غیرمرتبط با خودِ پروکسی کاندید را جریمه نمی‌کند و
    (True, 0.0) برمی‌گرداند تا فقط پروکسی‌های واقعاً از کار افتاده حذف شوند."""
    if scheme in ("hysteria2", "hy2"):
        return True, 0.0  # پروتکل پشتیبانی‌نشده توسط Xray-core؛ بدون قضاوت رد می‌شود

    outbound = build_xray_outbound(raw_config, scheme)
    if outbound is None:
        return True, 0.0  # نتوانستیم بسازیم؛ کاندید جریمه نمی‌شود

    local_port = _next_local_port()
    conf_path = f"/tmp/xray_{local_port}.json"
    conf = {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": local_port,
            "protocol": "http", "settings": {},
        }],
        "outbounds": [outbound],
    }

    proc = None
    try:
        with open(conf_path, "w") as f:
            json.dump(conf, f)

        proc = await asyncio.create_subprocess_exec(
            xray_path, "run", "-c", conf_path,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.sleep(0.8)
        if proc.returncode is not None:
            return False, 0.0  # پروسه زود بسته شد یعنی کانفیگ نامعتبر است

        proxy_url = f"http://127.0.0.1:{local_port}"
        ok = False
        for attempt in range(2):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        CFG.REAL_TEST_URL, proxy=proxy_url,
                        timeout=aiohttp.ClientTimeout(total=CFG.REAL_TEST_TIMEOUT),
                    ) as r:
                        ok = r.status in (200, 204)
                        break
            except Exception:
                if attempt == 0:
                    await asyncio.sleep(0.5)
                    continue
                return False, 0.0

        if not ok:
            return False, 0.0

        # اتصال واقعاً کار می‌کند — حالا با همین پروکسی یک دانلود کوچک
        # (~۱.۵ مگابایت از سرورهای کلادفلر) برای سنجش سرعت واقعی می‌زنیم.
        # هر خطا یا کندی اینجا فقط یعنی سرعت را نمی‌دانیم (0.0)، کاندید را
        # رد نمی‌کند — چون اصل اتصال از قبل تأیید شده است.
        speed_mbps = 0.0
        try:
            test_bytes = 1_500_000
            start = time.perf_counter()
            received = 0
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://speed.cloudflare.com/__down?bytes={test_bytes}",
                    proxy=proxy_url, timeout=aiohttp.ClientTimeout(total=6.0),
                ) as r:
                    async for chunk in r.content.iter_chunked(65536):
                        received += len(chunk)
            elapsed = max(time.perf_counter() - start, 0.05)
            if received > 0:
                speed_mbps = round((received * 8) / elapsed / 1_000_000, 1)
        except Exception:
            pass

        return True, speed_mbps
    except Exception as e:
        log.debug(f"real_test_one infra fail: {e}")
        return True, 0.0  # خطای زیرساختی ما، نه تقصیر پروکسی -> جریمه نکن
    finally:
        if proc is not None and proc.returncode is None:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
        try:
            os.remove(conf_path)
        except Exception:
            pass


async def run_real_tests(scored: List[ScoredNode]) -> List[ScoredNode]:
    if not CFG.REAL_TEST_ENABLED:
        return scored
    try:
        xray_path = await ensure_xray_binary()
    except Exception as e:
        log.warning(f"⚠️ تست واقعی به‌طور کامل رد شد: {e}")
        return scored
    if not xray_path:
        return scored

    candidates = scored[:CFG.REAL_TEST_MAX_CANDIDATES]
    rest = scored[CFG.REAL_TEST_MAX_CANDIDATES:]
    sem = asyncio.Semaphore(CFG.REAL_TEST_CONCURRENCY)

    async def _check(n: ScoredNode):
        async with sem:
            try:
                ok, speed = await real_test_one(xray_path, n.config, n.scheme)
            except Exception:
                ok, speed = True, 0.0  # هر خطای پیش‌بینی‌نشده -> جریمه نکن
            return n, ok, speed

    log.info(f"   🔎 تست واقعی روی {len(candidates)} کاندیدای برتر...")
    results = await asyncio.gather(*[_check(n) for n in candidates])
    verified = []
    for n, ok, speed in results:
        if not ok:
            continue
        n.speed_mbps = speed
        # جایزه‌ی امتیاز برای سرعت واقعی (حداکثر ۱۰۰ امتیاز برای ≥۵۰ مگابیت/ثانیه)
        n.score += min(speed, 50.0) * 2
        verified.append(n)
    verified.sort(key=lambda x: x.score, reverse=True)
    log.info(f"   ✅ {len(verified)} تأیید شد | ❌ {len(candidates) - len(verified)} رد شد")
    return verified + rest


# =============================================================================
# Main
# =============================================================================

async def main():
    start = time.time()
    log.info("=" * 60)
    log.info("🚀 V2Ray Smart Collector v2.1 (Fixed)")
    log.info("=" * 60)

    db = HistoryDB()

    try:
        log.info("📥 مرحله 1: دریافت از منابع...")
        fetcher = AsyncFetcher()
        raw = await fetcher.fetch_all(list(CFG.SOURCES))
        success_sources = sum(1 for t in raw if t)
        log.info(f"   ✅ {success_sources}/{len(CFG.SOURCES)} منبع موفق")

        log.info("🔓 مرحله 2: رمزگشایی و پارس...")
        all_configs = set()
        for text in raw:
            if not text:
                continue
            for decoded in ConfigDecoder.decode_all(text):
                for line in decoded.splitlines():
                    line = line.strip()
                    if line.startswith(CFG.ALLOWED_SCHEMES):
                        all_configs.add(line)
        log.info(f"   ✅ {len(all_configs)} کانفیگ یکتا (رشته‌ای)")

        parsed_list: List[ParsedConfig] = []
        parse_fail = 0
        for c in all_configs:
            pc = ConfigParser.parse(c)
            if pc:
                parsed_list.append(pc)
            else:
                parse_fail += 1
        log.info(f"   ✅ {len(parsed_list)} پارس موفق | {parse_fail} پارس ناموفق")

        # dedup بر اساس host:port قبل از تست (کاهش تست‌های تکراری)
        by_hostport = {}
        for pc in parsed_list:
            key = (pc.host, pc.port)
            if key not in by_hostport:
                by_hostport[key] = pc
        parsed_list = list(by_hostport.values())
        log.info(f"   ✅ {len(parsed_list)} پس از dedup بر اساس host:port")

        if len(parsed_list) > CFG.MAX_CANDIDATES:
            random.shuffle(parsed_list)
            parsed_list = parsed_list[:CFG.MAX_CANDIDATES]

        log.info("🧪 مرحله 3: تست شبکه...")
        tester = AdvancedTester()
        tested = tester.test_all(parsed_list)

        log.info("🌍 مرحله 4: جغرافیا (async)...")
        geo = GeoLocator(db)
        hosts = [r.host for r in tested]
        geo_map = await geo.resolve_all(hosts)
        log.info(f"   ✅ {len(geo_map)} میزبان geo-resolve شد ({geo.api_calls} کال API واقعی)")

        log.info("🎯 مرحله 5: امتیازدهی...")
        scorer = SmartScorer(db, geo_map)
        scored = scorer.score_all(tested)

        log.info("🧪 مرحله 5.5: تست واقعی اتصال (Xray)...")
        scored = await run_real_tests(scored)

        seen = set()
        final = []
        for n in scored:
            key = f"{n.host}:{n.port}"
            if key not in seen:
                seen.add(key)
                final.append(n)
            if len(final) >= CFG.TOP_N_FINAL:
                break
        log.info(f"   🏆 {len(final)} کانفیگ نهایی")

        for n in final:
            db.record(n.host, n.port, n.ping, n.score, success=True)

        log.info("📤 مرحله 6: ارسال به تلگرام...")
        sender = TelegramSender()
        parts = sender.build(final)
        await sender.send_all(parts)

        elapsed = time.time() - start
        log.info("=" * 60)
        log.info(f"✨ تمام شد در {elapsed:.1f}s")
        log.info(f"📊 خام: {len(all_configs)} | پارس: {len(parsed_list)} | "
                  f"تست: {len(tested)} | ارسال: {len(final)} | پارت: {len(parts)}")
        log.info("=" * 60)
        return 0

    except Exception as e:
        log.exception(f"❌ خطای بحرانی: {e}")
        return 1

    finally:
        db.close()


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code or 0)
    except KeyboardInterrupt:
        log.warning("⚠️ لغو شد توسط کاربر")
        sys.exit(130)
