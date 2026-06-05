# =============================================================================
#  modules/ocr_engine.py  — OCR-Based Evidence Analysis Engine
#
#  Extracts text from images/screenshots then runs full IOC extraction:
#    - URLs, Emails, IPs, Crypto Wallets, Phone Numbers
#    - Threat Intelligence auto-lookup on extracted IOCs
#    - Multiple image preprocessing pipelines for accuracy
#    - PDF page rendering + OCR
#    - Screenshot timeline reconstruction
# =============================================================================

import os, re, json, time, math, hashlib
import cv2
import numpy as np
import pytesseract
from PIL import Image, ImageFilter, ImageEnhance

# ---------------------------------------------------------------------------
# IOC patterns
# ---------------------------------------------------------------------------
_IPV4    = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
_URL     = re.compile(r'https?://[\w\-\./?=&%#+~@:]+', re.I)
_EMAIL   = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
_BTC     = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
_ETH     = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
_XMR     = re.compile(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b')
_PHONE   = re.compile(r'(?:\+?\d[\d\s\-\(\)]{7,15}\d)')
_CVE     = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.I)
_HASH_MD5    = re.compile(r'\b[a-fA-F0-9]{32}\b')
_HASH_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
_DOMAIN  = re.compile(r'\b(?:[a-zA-Z0-9\-]{1,63}\.)+(?:com|net|org|io|gov|edu|ru|cn|onion|xyz|top|cc|pw)\b', re.I)

# Suspicious keywords for context scoring
SUSPICIOUS_KW = [
    'password','credential','secret','ransom','bitcoin','pay','decrypt',
    'hack','exploit','stolen','leaked','dump','breach','confidential',
    'transfer','account','login','verify','suspended','click here',
    'winner','prize','urgent','bank','wire','western union',
]

PREPROCESS_MODES = ['original','grayscale','thresh','denoise','upscale','adaptive']


# =============================================================================
#  Image preprocessing pipelines
# =============================================================================

def _preprocess(img_path: str, mode: str) -> np.ndarray:
    img = cv2.imread(img_path)
    if img is None:
        pil = Image.open(img_path).convert('RGB')
        img = cv2.cvtColor(np.array(pil), cv2.COLOR_RGB2BGR)

    if mode == 'original':
        return img

    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    if mode == 'grayscale':
        return gray

    if mode == 'thresh':
        _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        return thresh

    if mode == 'denoise':
        denoised = cv2.fastNlMeansDenoising(gray, h=10)
        return denoised

    if mode == 'upscale':
        h, w = img.shape[:2]
        up = cv2.resize(img, (w*2, h*2), interpolation=cv2.INTER_CUBIC)
        return up

    if mode == 'adaptive':
        blurred = cv2.GaussianBlur(gray, (3,3), 0)
        adaptive = cv2.adaptiveThreshold(
            blurred, 255,
            cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
            cv2.THRESH_BINARY, 11, 2
        )
        return adaptive

    return img


def _ocr_image(img_array: np.ndarray, lang: str = 'eng') -> str:
    """Run Tesseract OCR on a preprocessed image array."""
    config = '--oem 3 --psm 6 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@._-/:?=&%+#~!$,;() '
    try:
        pil = Image.fromarray(img_array)
        text = pytesseract.image_to_string(pil, lang=lang, config=config)
        return text
    except Exception as e:
        return ""


def _best_ocr(img_path: str) -> tuple[str, str]:
    """Try all preprocessing modes, return the one with most text."""
    best_text = ""
    best_mode = "original"
    for mode in PREPROCESS_MODES:
        try:
            arr  = _preprocess(img_path, mode)
            text = _ocr_image(arr)
            if len(text.strip()) > len(best_text.strip()):
                best_text = text
                best_mode = mode
        except Exception:
            pass
    return best_text, best_mode


# =============================================================================
#  IOC extraction from OCR text
# =============================================================================

def _extract_iocs(text: str) -> dict:
    iocs = {
        'urls':      list(set(_URL.findall(text)))[:30],
        'ips':       list(set(_IPV4.findall(text)))[:30],
        'emails':    list(set(_EMAIL.findall(text)))[:20],
        'domains':   list(set(_DOMAIN.findall(text)))[:20],
        'btc':       list(set(_BTC.findall(text)))[:10],
        'eth':       list(set(_ETH.findall(text)))[:10],
        'xmr':       list(set(_XMR.findall(text)))[:5],
        'phones':    list(set(_PHONE.findall(text)))[:10],
        'cves':      list(set(_CVE.findall(text)))[:10],
        'md5':       list(set(_HASH_MD5.findall(text)))[:10],
        'sha256':    list(set(_HASH_SHA256.findall(text)))[:10],
    }
    # Filter noise
    iocs['ips'] = [ip for ip in iocs['ips']
                   if not ip.startswith(('0.','255.'))]
    iocs['md5'] = [h for h in iocs['md5'] if len(set(h)) > 4]
    return iocs


def _score_text(text: str, iocs: dict) -> dict:
    """Score extracted text for forensic relevance."""
    text_lower = text.lower()
    kw_hits = [kw for kw in SUSPICIOUS_KW if kw in text_lower]
    ioc_count = sum(len(v) for v in iocs.values())

    score = 0
    score += min(len(kw_hits)  * 8,  40)
    score += min(ioc_count     * 5,  30)
    score += 20 if iocs['btc'] or iocs['xmr'] else 0
    score += 15 if iocs['urls'] else 0
    score += 10 if iocs['emails'] else 0

    categories = []
    if any(kw in text_lower for kw in ['ransom','decrypt','bitcoin','pay','files encrypted']):
        categories.append('Ransomware')
    if any(kw in text_lower for kw in ['verify','suspended','click','account','bank','login']):
        categories.append('Phishing')
    if any(kw in text_lower for kw in ['password','credential','dump','leaked','breach']):
        categories.append('Credential Theft')
    if any(kw in text_lower for kw in ['wire transfer','western union','prize','winner','urgent']):
        categories.append('Fraud / Social Engineering')
    if iocs['btc'] or iocs['xmr']:
        categories.append('Cryptocurrency')

    return {
        'score':       min(score, 100),
        'kw_hits':     kw_hits[:10],
        'ioc_count':   ioc_count,
        'categories':  categories or ['General'],
    }


# =============================================================================
#  PDF page OCR
# =============================================================================

def _ocr_pdf(pdf_path: str, max_pages: int = 10) -> list[dict]:
    """Render PDF pages as images then OCR each page."""
    pages = []
    try:
        import subprocess
        # Use pdftoppm if available (poppler)
        out_dir = pdf_path + '_pages'
        os.makedirs(out_dir, exist_ok=True)
        subprocess.run(
            ['pdftoppm', '-r', '200', '-png', pdf_path,
             os.path.join(out_dir, 'page')],
            capture_output=True, timeout=30
        )
        page_files = sorted([
            os.path.join(out_dir, f)
            for f in os.listdir(out_dir)
            if f.endswith('.png')
        ])[:max_pages]

        for i, pf in enumerate(page_files):
            text, mode = _best_ocr(pf)
            iocs = _extract_iocs(text)
            scoring = _score_text(text, iocs)
            pages.append({
                'page':    i+1,
                'text':    text[:2000],
                'iocs':    iocs,
                'scoring': scoring,
                'mode':    mode,
            })
    except Exception as e:
        pages.append({'page':1,'text':f'PDF OCR error: {e}','iocs':{},'scoring':{},'mode':''})
    return pages


# =============================================================================
#  PUBLIC API
# =============================================================================

def analyse(filepath: str) -> dict:
    """
    Run full OCR analysis on an image or PDF.
    Returns structured result with extracted text, IOCs, scoring.
    """
    if not os.path.exists(filepath):
        return {'success': False, 'error': 'File not found'}

    ext  = os.path.splitext(filepath)[1].lower()
    name = os.path.basename(filepath)
    size = os.path.getsize(filepath)

    result = {
        'success':    True,
        'filename':   name,
        'size':       size,
        'ext':        ext,
        'pages':      [],
        'full_text':  '',
        'iocs':       {},
        'scoring':    {},
        'threat_intel': [],
        'engine':     'tesseract-5',
    }

    if ext == '.pdf':
        result['pages']     = _ocr_pdf(filepath)
        result['full_text'] = '\n\n'.join(p['text'] for p in result['pages'])
        # Merge IOCs across all pages
        merged = {}
        for page in result['pages']:
            for k, v in page.get('iocs',{}).items():
                merged.setdefault(k,[]).extend(v)
        result['iocs'] = {k: list(set(v))[:20] for k,v in merged.items()}
    elif ext in {'.jpg','.jpeg','.png','.bmp','.tiff','.tif','.gif','.webp'}:
        text, mode = _best_ocr(filepath)
        result['full_text'] = text
        result['best_mode'] = mode
        result['iocs']      = _extract_iocs(text)
        result['pages']     = [{'page':1,'text':text[:2000],
                                'iocs':result['iocs'],'mode':mode}]
    else:
        return {'success':False,'error':f'Unsupported file type: {ext}'}

    result['scoring'] = _score_text(result['full_text'], result['iocs'])

    # Auto threat intel on extracted hashes
    try:
        from modules.threat_intel import malwarebazaar_hash, threatfox_ioc
        ti = []
        for h in result['iocs'].get('sha256',[])[:3]:
            r = malwarebazaar_hash(h)
            if r.get('found'):
                ti.append({'source':'malwarebazaar','ioc':h,'result':r})
        for ip in result['iocs'].get('ips',[])[:3]:
            r = threatfox_ioc(ip)
            if r.get('found'):
                ti.append({'source':'threatfox','ioc':ip,'result':r})
        result['threat_intel'] = ti
    except Exception:
        pass

    return result
