# =============================================================================
#  modules/crime_classifier.py  -- Advanced Content-Based Crime Classifier v2
# =============================================================================

import os, re, math, pickle, json, warnings
import numpy as np
from sklearn.neural_network import MLPClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
warnings.filterwarnings("ignore")

MODEL_PATH  = "crime_clf_v2.pkl"
RANDOM_SEED = 42
IMAGE_EXTS  = {".jpg",".jpeg",".png",".bmp",".tiff",".tif",".gif",".webp"}

CRIME_CLASSES = [
    "Ransomware","Phishing","Remote Access Trojan","Keylogger / Spyware",
    "Data Exfiltration","Credential Theft","Cryptominer","Web Attack / Exploit",
    "Fraud / Social Engineering","DDoS / Botnet","Rootkit","Dropper / Loader",
    "Anti-Forensics","Harassment / Threat","Unknown Malware",
]

CRIME_SIGNATURES = {
    "Ransomware":             [b"ransom",b"encrypt",b"decrypt",b"bitcoin",b"YOUR_FILES",b"wannacry",b"cryptolocker",b".onion",b"shadow copies"],
    "Phishing":               [b"verify your account",b"account suspended",b"click here",b"PayPal",b"<form",b"update payment",b"unusual activity"],
    "Remote Access Trojan":   [b"meterpreter",b"CreateRemoteThread",b"VirtualAllocEx",b"WriteProcessMemory",b"reverse_shell",b"nc -e",b"bind shell"],
    "Keylogger / Spyware":    [b"GetAsyncKeyState",b"SetWindowsHookEx",b"WH_KEYBOARD",b"keylog",b"keystroke",b"clipboard"],
    "Data Exfiltration":      [b"ftp://",b"curl -T",b"exfiltrat",b"dns_tunnel",b"pastebin",b"DropBox",b"wget --post"],
    "Credential Theft":       [b"mimikatz",b"lsass",b"sekurlsa",b"Pass-the-Hash",b"golden ticket",b"NTLM",b"SAM database"],
    "Cryptominer":            [b"xmrig",b"monero",b"stratum+tcp",b"mining",b"hashrate",b"CryptoNight"],
    "Web Attack / Exploit":   [b"UNION SELECT",b"DROP TABLE",b"<script>alert(",b"../../etc/passwd",b"<?php system(",b"sqlmap",b"Log4j"],
    "Fraud / Social Engineering":[b"Western Union",b"wire transfer",b"you have won",b"lottery",b"inheritance",b"advance fee"],
    "DDoS / Botnet":          [b"botnet",b"zombie",b"flood",b"syn flood",b"LOIC",b"HOIC"],
    "Rootkit":                [b"ring0",b"SSDT",b"IRP",b"DriverEntry",b"ZwCreateFile",b"hooking",b"stealth"],
    "Dropper / Loader":       [b"dropper",b"loader",b"shellcode",b"RunPE",b"URLDownloadToFile",b"certutil",b"reflective"],
    "Anti-Forensics":         [b"wevtutil cl",b"cipher /w",b"format c:",b"del /f /q /s",b"rm -rf",b"shred",b"DBAN"],
    "Harassment / Threat":    [b"kill you",b"bomb",b"doxx",b"sextortion",b"i know where",b"revenge",b"threatening"],
    "Unknown Malware":        [b"cmd.exe",b"powershell",b"WScript",b"eval(",b"CreateObject"],
}

_ml_cache = None

def _build_corpus():
    import random
    rng = random.Random(RANDOM_SEED)
    templates = {
        "Ransomware":["Your files encrypted pay bitcoin decrypt DECRYPT_INSTRUCTIONS","WannaCry ransomware shadow copies deleted payment deadline","CryptoLocker payload executed file extension locked bitcoin wallet","All documents encrypted ransom demand YOUR_FILES_ARE_LOCKED","ransom notice files locked AES-256 bitcoin payment required decrypt key"],
        "Phishing":["account suspended verify identity click here PayPal Security Alert","Bank account limited update payment information immediately alert","Apple ID suspended verify account 24 hours avoid suspension","IRS Tax Refund pending submit banking details confirm identity","unusual activity detected confirm credentials restore access bank"],
        "Remote Access Trojan":["meterpreter session established CreateRemoteThread injection reverse shell","bind shell listening VirtualAllocEx WriteProcessMemory backdoor C2","RAT deployed credentials harvested exfiltration started C2 beacon","payload injected explorer.exe reverse shell command control active","RtlCreateUserThread remote access backdoor persistent connection"],
        "Keylogger / Spyware":["GetAsyncKeyState hook WH_KEYBOARD_LL keystroke capture clipboard monitor","Keylogger screen capture email log SetWindowsHookEx keyboard hook","keystroke logging hidden file browser history passwords extracted","Screen recorder microphone GPS location tracking WH_KEYBOARD","keyboard hook registered all keystrokes logged spyware active"],
        "Data Exfiltration":["curl ftp exfiltration sensitive files transferred attacker server","DNS tunneling base64 encoded data transmitted exfiltration pastebin","files compressed uploaded DropBox data theft successful","Database dump uploaded remote server credentials exfiltrated SFTP","wget post-file credentials http attacker dns tunnel operation"],
        "Credential Theft":["mimikatz sekurlsa logonpasswords NTLM hash dumped Pass-the-Hash","lsass memory dumped SAM database stolen procdump executed","Kerberos ticket harvested lateral movement domain admin compromised","CredEnumerate Windows Credential Store passwords extracted","hashcat cracking NTLM hashes domain controller SAM registry"],
        "Cryptominer":["xmrig monero mining stratum+tcp pool hashrate CPU 95 percent","CryptoNight GPU miner launched mining pool connected wallet","Cryptocurrency miner deployed CPU throttled mining revenue","Monero XMR mining pool stratum protocol connected hashrate","Unauthorized mining software high CPU network connections pools"],
        "Web Attack / Exploit":["UNION SELECT username password SQL injection sqlmap bypass","script alert XSS payload injected comment field stored","etc passwd LFI traversal PHP file inclusion eval base64","Log4Shell CVE-2021-44228 JNDI lookup exploitation ldap","DROP TABLE SQL injection admin panel compromised web shell"],
        "Fraud / Social Engineering":["won 1.5 million dollars lottery send banking details claim","Nigerian prince transfer 40 million USD bank account advance fee","Inheritance deceased relative 25 million advance fee wire","Western Union wire transfer business proposal confidential urgent","URGENT back taxes iTunes gift cards arrest pay immediately"],
        "DDoS / Botnet":["LOIC SYN flood botnet zombie DDoS target activated","UDP flood amplification DNS NTP botnet all nodes TCP","Botnet 50000 machines DDoS attack volumetric bandwidth","HOIC botnet C2 flood bandwidth saturation disruption","distributed denial service zombie infection spreading nodes"],
        "Rootkit":["ring0 kernel SSDT hook IRP DriverEntry NtCreateFile hidden process","Kernel-mode rootkit DKOM process hiding SSDT modification stealth","ZwCreateFile hook registry key hidden MBR infection persistent","Bootkit UEFI firmware stealth rootkit kernel process file hiding","DKOM manipulation rootkit hides malicious process task manager"],
        "Dropper / Loader":["Dropper URLDownloadToFile payload reflective injection RunPE","Stage 1 loader certutil decode shellcode injected memory execution","bitsadmin transfer DLL regsvr32 execution AppLocker bypass","mshta HTA dropper VBScript payload NtUnmapViewOfSection","process hollowing RunPE payload injected clean process reflective"],
        "Anti-Forensics":["wevtutil cl System Security logs cleared artifacts destroyed","cipher free space wiped Eraser secure deletion disk wipe","del /f /q /s Volume Shadow Copies deleted vssadmin shadows","timestomp timestamps modified Prefetch deleted Registry cleared","shred files DBAN disk wipe bootable USB evidence elimination"],
        "Harassment / Threat":["I know where you live kill you death threat cannot hide","Sextortion intimate photos pay bitcoin send contacts revenge","Bomb threat building destroyed demands do not contact police","Doxxing personal information home address published harassment","You will regret this photos videos destroy reputation pay"],
        "Unknown Malware":["cmd.exe powershell -EncodedCommand WScript.Shell CreateObject suspicious","regsvr32 /s /n /u /i http scrobj AppLocker bypass technique","mshta vbscript Execute CreateObject Shell Run cmd.exe malicious","bitsadmin transfer payload http start suspicious download execution","certutil urlcache split decode http shell execution suspicious"],
    }
    docs, labels = [], []
    for crime, tmpl_list in templates.items():
        for tmpl in tmpl_list:
            docs.append(tmpl); labels.append(crime)
            for _ in range(5):
                words = tmpl.split(); rng.shuffle(words)
                docs.append(" ".join(words)); labels.append(crime)
    return docs, labels

def train_ml_classifier(force=False):
    global _ml_cache
    if not force and os.path.exists(MODEL_PATH):
        try:
            with open(MODEL_PATH,"rb") as f: _ml_cache = pickle.load(f); return _ml_cache
        except Exception: pass
    docs, labels = _build_corpus()
    Xtr,Xte,ytr,yte = train_test_split(docs,labels,test_size=0.2,random_state=RANDOM_SEED,stratify=labels)
    mlp = Pipeline([("tfidf",TfidfVectorizer(ngram_range=(1,3),max_features=6000,sublinear_tf=True,min_df=1)),
                    ("clf",MLPClassifier(hidden_layer_sizes=(128,64,32),activation="relu",solver="adam",alpha=1e-3,max_iter=500,random_state=RANDOM_SEED,early_stopping=True,validation_fraction=0.15))])
    rf  = Pipeline([("tfidf",TfidfVectorizer(ngram_range=(1,2),max_features=4000,sublinear_tf=True,min_df=1)),
                    ("clf",RandomForestClassifier(n_estimators=200,random_state=RANDOM_SEED,n_jobs=-1,class_weight="balanced"))])
    mlp.fit(Xtr,ytr); rf.fit(Xtr,ytr)
    y_pred = [a if a==b else a for a,b in zip(mlp.predict(Xte),rf.predict(Xte))]
    bundle = {"mlp":mlp,"rf":rf,"accuracy":round(accuracy_score(yte,y_pred)*100,2),"classes":CRIME_CLASSES}
    with open(MODEL_PATH,"wb") as f: pickle.dump(bundle,f)
    _ml_cache = bundle; return bundle

def _get_model():
    global _ml_cache
    if _ml_cache: return _ml_cache
    return train_ml_classifier()

def _pattern_score(filepath):
    scores = {c:0 for c in CRIME_CLASSES}; evidence = {c:[] for c in CRIME_CLASSES}
    try:
        with open(filepath,"rb") as f: raw = f.read(min(os.path.getsize(filepath),512*1024))
    except Exception: return scores, evidence
    raw_lower = raw.lower()
    for crime, patterns in CRIME_SIGNATURES.items():
        for pat in patterns:
            if pat.lower() in raw_lower: scores[crime]+=12; evidence[crime].append(pat.decode("utf-8","ignore")[:50])
    return scores, evidence

def _ml_predict(text):
    if not text.strip(): return {"predicted":"Unknown Malware","confidence":0,"probs":{}}
    m = _get_model()
    mlp_p = m["mlp"].predict_proba([text])[0]; rf_p = m["rf"].predict_proba([text])[0]
    avg = (mlp_p+rf_p)/2; cls = m["mlp"].classes_; idx = int(np.argmax(avg))
    return {"predicted":cls[idx],"confidence":round(float(avg[idx])*100,1),"probs":{c:round(float(p)*100,1) for c,p in zip(cls,avg)}}

def _severity_from_crime(crime):
    if any(c in crime for c in ["Homicide","Terrorism","Ransomware","Credential Theft","Rootkit"]): return "CRITICAL"
    if any(c in crime for c in ["RAT","Trojan","Keylogger","Exfiltration","Web Attack","Dropper","Phishing","Assault","Drug","Arson"]): return "HIGH"
    return "MEDIUM"

def classify(filepath):
    ext = os.path.splitext(filepath)[1].lower()
    if ext in IMAGE_EXTS:
        try:
            from modules.crime_detection import detect
            r = detect(filepath)
            if r.get("success"):
                return {"predicted_crime":r["crime_type"],"confidence":float(r["confidence"]),"score":float(r["confidence"]),
                        "top3":[{"crime":m["crime"],"score":m["score"]} for m in r.get("all_crime_matches",[])[:3]],
                        "all_scores":{m["crime"]:m["score"] for m in r.get("all_crime_matches",[])},
                        "evidence":[d.get("detail","") for d in r.get("detected_objects",[])[:5]],
                        "explanation":r.get("forensic_summary",""),"method":f'vision_{r.get("engine","")}',
                        "severity":r.get("severity","LOW")}
        except Exception: pass
    pat_scores,pat_evidence = _pattern_score(filepath)
    try:
        with open(filepath,"rb") as f: raw=f.read(min(os.path.getsize(filepath),128*1024))
        text=raw.decode("utf-8","replace")
        ml_pred = _ml_predict(text) if len(text.strip())>20 else {"predicted":"Unknown Malware","confidence":0,"probs":{}}
    except Exception: ml_pred={"predicted":"Unknown Malware","confidence":0,"probs":{}}
    combined={c:pat_scores[c]+ml_pred["probs"].get(c,0)*0.4 for c in CRIME_CLASSES}
    ext=os.path.splitext(filepath)[1].lower()
    if ext in {".exe",".dll",".bat",".scr",".ps1",".vbs"}:
        for c in ["Remote Access Trojan","Rootkit","Dropper / Loader","Ransomware"]: combined[c]+=8
    if ext in {".php",".html",".htm"}: combined["Web Attack / Exploit"]+=8; combined["Phishing"]+=6
    sorted_c=sorted(combined.items(),key=lambda x:-x[1])
    top=sorted_c[0]; confidence=round(min(top[1]/150*100,99),1)
    crime=top[0] if confidence>=25 else "Unknown Malware"
    return {"predicted_crime":crime,"confidence":confidence,"score":confidence,
            "top3":[{"crime":c,"score":round(min(s/150*100,99),1)} for c,s in sorted_c[:3]],
            "all_scores":{c:round(min(s/150*100,99),1) for c,s in sorted_c},
            "evidence":pat_evidence.get(crime,[])[:5],
            "explanation":f"Classified as {crime!r} ({confidence:.0f}% confidence) via pattern+ML ensemble.",
            "method":"pattern_ml_ensemble","ml_prediction":ml_pred["predicted"],
            "ml_confidence":ml_pred["confidence"],"severity":_severity_from_crime(crime)}
