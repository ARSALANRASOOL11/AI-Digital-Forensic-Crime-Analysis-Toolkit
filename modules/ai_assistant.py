# =============================================================================
#  modules/ai_assistant.py  — AI Investigation Assistant
#
#  Uses Ollama (Llama 3 / Mistral / Gemma) when available.
#  Graceful offline fallback to the built-in rule-based analyst.
#
#  Ollama setup:
#    1. Install: https://ollama.ai
#    2. Pull model: ollama pull llama3
#                   ollama pull mistral
#                   ollama pull gemma2
#    3. Start:   ollama serve   (runs on localhost:11434)
#
#  The system prompt gives the LLM full context about the case —
#  evidence list, risk scores, YARA hits, IOCs, crime types —
#  so it can answer complex forensic questions in natural language.
# =============================================================================

import os, json, time, re, urllib.request, urllib.error

OLLAMA_BASE    = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_TIMEOUT = 60
DEFAULT_MODEL  = os.environ.get("OLLAMA_MODEL", "llama3")

# Fallback models to try in order
MODEL_PRIORITY = ["llama3", "llama3.1", "llama3.2", "mistral",
                  "mistral-nemo", "gemma2", "phi3", "qwen2",
                  "deepseek-r1", "codellama"]

# MITRE ATT&CK knowledge base for offline fallback
MITRE_KB = {
    "T1059": "Command and Scripting Interpreter — attacker runs commands via cmd/PowerShell",
    "T1486": "Data Encrypted for Impact — ransomware encrypts victim files",
    "T1071": "Application Layer Protocol — C2 traffic hidden in HTTP/DNS",
    "T1055": "Process Injection — malware injects code into legitimate processes",
    "T1003": "OS Credential Dumping — stealing password hashes from LSASS/SAM",
    "T1547": "Boot/Logon Autostart — malware persists via registry Run key",
    "T1566": "Phishing — initial access via malicious email attachment",
    "T1190": "Exploit Public-Facing Application — web server exploitation",
    "T1027": "Obfuscated Files — base64/encoding used to hide malicious content",
    "T1048": "Exfiltration Over Alternative Protocol — data stolen via DNS/FTP",
}


# =============================================================================
#  Ollama connection
# =============================================================================

def _ollama_get(endpoint: str) -> dict | None:
    try:
        req = urllib.request.Request(f"{OLLAMA_BASE}{endpoint}")
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())
    except Exception:
        return None


def _ollama_chat(model: str, messages: list,
                 stream: bool = False) -> str | None:
    payload = json.dumps({
        "model":    model,
        "messages": messages,
        "stream":   stream,
        "options":  {"temperature": 0.3, "num_predict": 1024},
    }).encode()
    try:
        req = urllib.request.Request(
            f"{OLLAMA_BASE}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=OLLAMA_TIMEOUT) as r:
            raw = r.read().decode("utf-8", "ignore")
            # Non-streaming: single JSON
            data = json.loads(raw)
            return data.get("message", {}).get("content", "")
    except urllib.error.URLError:
        return None
    except Exception:
        return None


def get_ollama_status() -> dict:
    """Check Ollama availability and list installed models."""
    info = _ollama_get("/api/tags")
    if info is None:
        return {"available": False, "models": [], "message":
                "Ollama not running. Install from https://ollama.ai then run: ollama serve"}
    models = [m["name"] for m in info.get("models", [])]
    return {"available": True, "models": models,
            "message": f"{len(models)} model(s) installed"}


def _pick_model() -> str | None:
    """Pick the best available model."""
    status = get_ollama_status()
    if not status["available"] or not status["models"]:
        return None
    installed = status["models"]
    for preferred in MODEL_PRIORITY:
        for inst in installed:
            if preferred in inst.lower():
                return inst
    return installed[0] if installed else None


# =============================================================================
#  System prompt builder — gives LLM full forensic context
# =============================================================================

def _build_system_prompt(evidence_context: dict) -> str:
    ev_list = evidence_context.get("evidence", [])
    summary = evidence_context.get("summary", {})

    ev_text = ""
    for e in ev_list[:20]:
        ev_text += (f"\n  - [{e.get('case_id','')}] {e.get('filename','')} | "
                    f"Risk: {e.get('risk_level','')} ({e.get('risk_score',0)}/100) | "
                    f"Crime: {e.get('crime_type','')} | "
                    f"Integrity: {e.get('integrity','')} | "
                    f"YARA: {e.get('yara_count',0)} hits")

    return f"""You are an expert digital forensic investigator AI assistant embedded in 
the Cyber Forensic Intelligence System (CFIS). You have direct access to the evidence database.

CASE SUMMARY:
- Total evidence files: {summary.get('total',0)}
- Cases: {summary.get('cases',0)}
- Tampered files: {summary.get('tampered',0)}
- High risk files: {summary.get('high_risk',0)}
- Crime types found: {', '.join(summary.get('crime_types',[]))}

EVIDENCE DATABASE:
{ev_text or '  (no evidence uploaded yet)'}

YOUR CAPABILITIES:
- Analyse patterns across all evidence files
- Identify attack chains and threat actor TTPs
- Recommend investigation priorities
- Explain MITRE ATT&CK techniques in context
- Suggest next forensic steps
- Cross-reference IOCs across cases
- Generate investigation hypotheses

RULES:
- Be concise but thorough
- Always cite specific evidence files when making claims
- Use forensic terminology but explain it clearly
- Flag when you are uncertain
- Prioritise actionable intelligence

Respond to the investigator's question below."""


# =============================================================================
#  Context builder from DB evidence
# =============================================================================

def build_evidence_context(evidence_rows: list) -> dict:
    """Build rich context dict from evidence DB rows."""
    from modules.analysis import ai_risk_score
    from modules.upload_security import verify_file
    from modules.yara_scanner import scan_file

    ev_list    = []
    crime_types = set()
    tampered   = 0
    high_risk  = 0
    cases      = set()

    for row in evidence_rows:
        name  = row[2] if not hasattr(row,"keys") else row["filename"]
        path  = row[3] if not hasattr(row,"keys") else row["path"]
        cid   = row[1] if not hasattr(row,"keys") else row["case_id"]
        fhash = row[4] if not hasattr(row,"keys") else row.get("hash","")
        crime = row[6] if (not hasattr(row,"keys") and len(row)>6) else "Unknown"

        cases.add(cid)
        if crime: crime_types.add(crime)

        integrity = "UNKNOWN"
        risk_lvl  = "UNKNOWN"
        risk_sc   = 0
        yara_n    = 0

        if os.path.exists(path):
            try:
                integrity = verify_file(path, fhash)
                risk      = ai_risk_score(name, path)
                risk_lvl  = risk["level"]
                risk_sc   = risk["score"]
                yara_n    = len(scan_file(path))
            except Exception:
                pass

        if integrity == "TAMPERED": tampered += 1
        if risk_lvl  == "HIGH_RISK": high_risk += 1

        ev_list.append({
            "case_id":    cid,
            "filename":   name,
            "risk_level": risk_lvl,
            "risk_score": risk_sc,
            "integrity":  integrity,
            "crime_type": crime,
            "yara_count": yara_n,
        })

    return {
        "evidence": ev_list,
        "summary":  {
            "total":       len(ev_list),
            "cases":       len(cases),
            "tampered":    tampered,
            "high_risk":   high_risk,
            "crime_types": list(crime_types),
        }
    }


# =============================================================================
#  Main chat function
# =============================================================================

def chat(question: str, history: list,
         evidence_context: dict) -> dict:
    """
    Process a question from the investigator.
    Returns {"reply": str, "source": "ollama|fallback", "model": str}
    """
    model = _pick_model()

    if model:
        # --- Ollama path ---
        system_prompt = _build_system_prompt(evidence_context)
        messages = [{"role": "system", "content": system_prompt}]

        # Include recent history (last 6 turns)
        for turn in history[-6:]:
            messages.append({"role": "user",      "content": turn["question"]})
            messages.append({"role": "assistant",  "content": turn["answer"]})

        messages.append({"role": "user", "content": question})

        reply = _ollama_chat(model, messages)
        if reply:
            return {"reply": reply, "source": "ollama", "model": model}

    # --- Offline fallback ---
    reply = _offline_analyst(question, evidence_context)
    return {"reply": reply, "source": "fallback", "model": "built-in"}


# =============================================================================
#  Offline analyst (rule-based, no LLM needed)
# =============================================================================

def _offline_analyst(q: str, ctx: dict) -> str:
    q     = q.lower().strip()
    ev    = ctx.get("evidence", [])
    summ  = ctx.get("summary", {})
    total = summ.get("total", 0)

    if total == 0:
        return ("No evidence in the database yet. Upload files via **Upload Evidence** "
                "to begin analysis. I can then answer questions about risk, tampering, "
                "crime types, IOCs, and investigation priorities.")

    # Tampered files
    if any(w in q for w in ["tamper","modif","changed","corrupt","integrity"]):
        t = [e for e in ev if e.get("integrity") == "TAMPERED"]
        if not t:
            return (f"✅ **No tampered files detected.** All {total} files passed "
                    f"SHA-256 integrity verification — evidence chain is intact.")
        lines = "\n".join(f"- **{e['filename']}** ({e['case_id']}) — hash mismatch" for e in t)
        return (f"⚠️ **{len(t)} tampered file(s) detected:**\n{lines}\n\n"
                f"**Action:** Quarantine these files and document the chain of custody break. "
                f"Cross-reference the modification timestamp with user activity logs.")

    # High risk
    if any(w in q for w in ["high risk","dangerous","threat","critical","malware","risky"]):
        hi = [e for e in ev if e.get("risk_level") == "HIGH_RISK"]
        cr = [e for e in ev if e.get("risk_level") == "CRITICAL"]
        if not hi and not cr:
            return "✅ No high-risk files found. All evidence has acceptable risk scores."
        out = f"🔴 **{len(hi)+len(cr)} high-risk / critical file(s):**\n"
        for e in (cr+hi)[:10]:
            out += f"- **{e['filename']}** | Score: {e['risk_score']}/100 | Crime: {e['crime_type']}\n"
        out += "\n**Recommended action:** Run sandbox analysis and IOC extraction on these files immediately."
        return out

    # Summary / overview
    if any(w in q for w in ["summarize","summary","overview","report","status","briefing"]):
        t   = summ.get("tampered",0)
        h   = summ.get("high_risk",0)
        cas = summ.get("cases",0)
        cts = ", ".join(summ.get("crime_types",[])[:5]) or "None detected"
        avg = round(sum(e.get("risk_score",0) for e in ev)/total, 1) if total else 0
        return (f"## 📋 Case Intelligence Briefing\n\n"
                f"**Evidence:** {total} files across {cas} case(s)\n"
                f"**Integrity:** {'⚠️ ' + str(t) + ' tampered' if t else '✅ All intact'}\n"
                f"**High Risk:** {'🔴 ' + str(h) + ' files' if h else '✅ None'}\n"
                f"**Avg Risk Score:** {avg}/100\n"
                f"**Crime Types:** {cts}\n\n"
                f"**Priority:** {'Investigate tampered files first.' if t else 'Focus on high-risk files.' if h else 'Standard evidence review.'}")

    # Crime type analysis
    if any(w in q for w in ["crime","type","classify","category","ransomware","phish","rat","malware"]):
        from collections import Counter
        ct_counts = Counter(e.get("crime_type","Unknown") for e in ev if e.get("crime_type"))
        if not ct_counts:
            return "No crime types classified yet. Upload and analyse evidence files first."
        out = "## 🔍 Crime Type Analysis\n\n"
        for ct, count in ct_counts.most_common(8):
            files = [e["filename"] for e in ev if e.get("crime_type") == ct][:3]
            out += f"**{ct}** ({count} file{'s' if count>1 else ''}): {', '.join(files)}\n"
        return out

    # MITRE ATT&CK
    if any(w in q for w in ["mitre","att&ck","ttp","technique","tactic"]):
        out = "## 🎯 MITRE ATT&CK Techniques (relevant to your evidence)\n\n"
        crime_types = set(e.get("crime_type","") for e in ev)
        relevant = []
        if any("ransom" in ct.lower() for ct in crime_types):
            relevant += ["T1486","T1490","T1027"]
        if any("rat" in ct.lower() or "remote" in ct.lower() for ct in crime_types):
            relevant += ["T1055","T1071","T1547"]
        if any("cred" in ct.lower() or "keylog" in ct.lower() for ct in crime_types):
            relevant += ["T1003","T1056","T1539"]
        relevant = relevant or list(MITRE_KB.keys())[:5]
        for ttp in relevant[:6]:
            if ttp in MITRE_KB:
                out += f"**{ttp}** — {MITRE_KB[ttp]}\n"
        return out

    # Next steps / what to do
    if any(w in q for w in ["next","should i","recommend","priority","what to do","investigate first"]):
        steps = []
        t = summ.get("tampered",0)
        h = summ.get("high_risk",0)
        if t:
            steps.append(f"1. 🔴 **Immediately** review {t} tampered file(s) — evidence integrity broken")
        if h:
            steps.append(f"2. 🟠 Run **Sandbox Analysis** on {h} high-risk file(s)")
        steps.append("3. 🟡 Run **IOC Extraction** on all evidence and submit hashes to Threat Intel")
        steps.append("4. 🟢 Check **Chain of Custody** log for any unexplained access events")
        steps.append("5. 📄 Generate **PDF Report** for each case with current findings")
        return "## 🗺️ Recommended Investigation Steps\n\n" + "\n".join(steps)

    # Case questions
    if any(w in q for w in ["case","how many","count","list"]):
        cases = {}
        for e in ev:
            cid = e.get("case_id","?")
            cases.setdefault(cid, []).append(e["filename"])
        out = f"## 📁 Cases ({len(cases)} total)\n\n"
        for cid, files in list(cases.items())[:10]:
            out += f"**{cid}** — {len(files)} file(s): {', '.join(files[:3])}\n"
        return out

    # Default
    return (f"I have analysed **{total} evidence file(s)** across "
            f"**{summ.get('cases',0)} case(s)**.\n\n"
            f"You can ask me:\n"
            f"- *'Which files are tampered?'*\n"
            f"- *'Show high risk files'*\n"
            f"- *'Summarize the case'*\n"
            f"- *'What crime types are present?'*\n"
            f"- *'What MITRE ATT&CK techniques apply?'*\n"
            f"- *'What should I investigate first?'*\n\n"
            f"💡 **Tip:** Install [Ollama](https://ollama.ai) and run `ollama pull llama3` "
            f"for full AI-powered natural language analysis.")
