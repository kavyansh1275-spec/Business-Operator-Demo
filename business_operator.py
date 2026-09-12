from __future__
import csv, hashlib, json, re, sqlite3, time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / 'data'
DB = DATA / 'business_operator.db'
INBOX = DATA / 'inbox'
ARCHIVE = DATA / 'archive'
for p in (DATA, INBOX, ARCHIVE): p.mkdir(parents=True, exist_ok=True)

@dataclass
class Finding:
    id: str
    business_id: str
    kind: str
    severity: str
    priority: int
    title: str
    message: str
    entity_id: str
    impact: float
    confidence: int
    reasons: list[str]
    recommended_action: str
    status: str = 'open'

def money(v):
    if v is None: return None
    s = str(v).strip().replace(',', '').replace('₹','').replace('$','')
    s = re.sub(r'[^0-9.\-]', '', s)
    try: return round(float(s), 2)
    except ValueError: return None

def norm_id(v): return re.sub(r'[^a-z0-9]', '', str(v or '').lower())
def norm_text(v): return re.sub(r'\s+', ' ', str(v or '').strip().lower())

def confidence(row):
    score = 35
    if row.get('id'): score += 25
    if row.get('customer'): score += 10
    if row.get('amount') is not None: score += 20
    if row.get('date'): score += 10
    return min(score, 100)

def db():
    con = sqlite3.connect(DB); con.row_factory = sqlite3.Row; con.execute('PRAGMA journal_mode=WAL'); return con

def init_db():
    with db() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS businesses(id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY AUTOINCREMENT, business_id TEXT NOT NULL, source TEXT NOT NULL, record_type TEXT NOT NULL, entity_id TEXT, customer TEXT, amount REAL, date TEXT, raw_json TEXT, confidence INTEGER, fingerprint TEXT, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY, business_id TEXT NOT NULL, kind TEXT, severity TEXT, priority INTEGER, title TEXT, message TEXT, entity_id TEXT, impact REAL, confidence INTEGER, reasons TEXT, recommended_action TEXT, status TEXT, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, business_id TEXT, event TEXT, details TEXT, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS actions(id TEXT PRIMARY KEY, business_id TEXT, finding_id TEXT, action_type TEXT, description TEXT, status TEXT, created_at TEXT NOT NULL, executed_at TEXT);
        ''')

def ensure_business(bid='demo', name='Demo Business'):
    with db() as c: c.execute('INSERT OR IGNORE INTO businesses VALUES (?,?,?)', (bid,name,datetime.utcnow().isoformat()))

def parse_file(path: Path):
    ext = path.suffix.lower()
    if ext == '.csv':
        with path.open('r', encoding='utf-8-sig', newline='') as f: return list(csv.DictReader(f))
    if ext == '.json':
        obj = json.loads(path.read_text(encoding='utf-8')); return obj if isinstance(obj, list) else obj.get('records', [])
    if ext == '.pdf':
        try:
            from pypdf import PdfReader
            text='\n'.join((p.extract_text() or '') for p in PdfReader(str(path)).pages)
            ids = re.findall(r'(?:invoice|order)\s*(?:id|no|number)?\s*[:#-]?\s*([A-Z0-9-]{3,})', text, re.I)
            amounts = re.findall(r'(?:total|amount|grand total)\D{0,20}(?:₹|Rs\.?|INR)?\s*([0-9][0-9,]*(?:\.\d{1,2})?)', text, re.I)
            cust = re.search(r'(?:customer|client|buyer)\s*[:#-]?\s*(.+)', text, re.I)
            return [{'id': ids[0] if ids else path.stem, 'customer': cust.group(1).strip() if cust else '', 'amount': amounts[-1] if amounts else '', 'date':'', '_text':text}]
        except Exception as e: return [{'_error': f'PDF unavailable: {e}', 'id': path.stem}]
    return []

def canonical(raw):
    def get(*keys):
        for k in keys:
            if k in raw and str(raw[k]).strip(): return raw[k]
        low={str(k).lower().strip():v for k,v in raw.items()}
        for k in keys:
            if k.lower() in low and str(low[k.lower()]).strip(): return low[k.lower()]
        return ''
    rid = get('record_id','id','invoice_id','invoice','transaction_id','payment_id','order_id','order')
    amount = money(get('amount','total','invoice_amount','order_amount','payment','paid','value'))
    return {'id':str(rid).strip(), 'customer':str(get('customer','customer_name','client','buyer')).strip(), 'amount':amount, 'date':str(get('date','invoice_date','order_date','payment_date')).strip(), 'raw':raw}

def fingerprint(r):
    s='|'.join([norm_id(r['id']),norm_text(r['customer']),str(r['amount']),norm_text(r['date'])]); return hashlib.sha256(s.encode()).hexdigest()

def ingest(business_id='demo'):
    ensure_business(business_id); imported=0
    with db() as c:
        for p in sorted(INBOX.iterdir()):
            if p.suffix.lower() not in {'.csv','.json','.pdf'}: continue
            for raw in parse_file(p):
                r=canonical(raw)
                if '_error' in raw: continue
                fp=fingerprint(r)
                if c.execute('SELECT 1 FROM records WHERE business_id=? AND fingerprint=?',(business_id,fp)).fetchone(): continue
                c.execute('INSERT INTO records(business_id,source,record_type,entity_id,customer,amount,date,raw_json,confidence,fingerprint,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)',(business_id,p.name,'business_record',r['id'],r['customer'],r['amount'],r['date'],json.dumps(raw),confidence(r),fp,datetime.utcnow().isoformat())); imported+=1
            try: p.rename(ARCHIVE / f'{int(time.time())}_{p.name}')
            except OSError: pass
        c.execute('INSERT INTO audit(business_id,event,details,created_at) VALUES(?,?,?,?)',(business_id,'ingest',json.dumps({'imported':imported}),datetime.utcnow().isoformat()))
    analyze(business_id); return imported

def analyze(business_id='demo'):
    with db() as c:
        rows=c.execute('SELECT * FROM records WHERE business_id=? ORDER BY id',(business_id,)).fetchall(); findings=[]; byid={}
        for r in rows:
            if r['entity_id']: byid.setdefault(norm_id(r['entity_id']),[]).append(r)
            if r['confidence'] < 60: findings.append(make_finding(business_id,'data_quality','medium',60,f'Low confidence record {r["entity_id"]}',f'Record {r["entity_id"] or r["id"]} has incomplete identifying information.',r['entity_id'],0,r['confidence'],['Missing one or more key fields'],'Review the source record and correct missing fields.'))
        for key, group in byid.items():
            if len(group)>1:
                amounts={r['amount'] for r in group if r['amount'] is not None}; customers={norm_text(r['customer']) for r in group if r['customer']}
                if len(amounts)>1: findings.append(make_finding(business_id,'conflict','high',95,f'Conflicting amounts for {group[0]["entity_id"]}',f'The same record ID appears with different amounts: {sorted(amounts)}.',group[0]['entity_id'],max(amounts)-min(amounts),95,['Same ID appears more than once','Amounts disagree'],'Verify the authoritative invoice/order/payment and correct the source.'))
                elif len(customers)>1: findings.append(make_finding(business_id,'conflict','medium',75,f'Conflicting customer for {group[0]["entity_id"]}','The same record ID is associated with different customers.',group[0]['entity_id'],0,90,['Same ID appears with different customer names'],'Verify the customer attached to the record.'))
                else: findings.append(make_finding(business_id,'duplicate','medium',70,f'Duplicate record {group[0]["entity_id"]}','The same business record appears multiple times with matching key fields.',group[0]['entity_id'],0,98,['Identical normalized business identifier','Matching key fields'],'Confirm whether one copy should be removed.'))
        orders={norm_id(r['entity_id']):r for r in rows if 'order' in norm_text(r['raw_json']) and r['amount'] is not None}; payments={}
        for r in rows:
            if 'payment' not in norm_text(r['raw_json']) or r['amount'] is None: continue
            try: raw=json.loads(r['raw_json'])
            except Exception: raw={}
            linked=raw.get('order_id') or raw.get('order') or raw.get('orderId') or r['entity_id']; payments[norm_id(linked)]=r
        for oid,o in orders.items():
            if oid in payments and abs(o['amount']-payments[oid]['amount'])>=0.01:
                diff=round(o['amount']-payments[oid]['amount'],2)
                if diff>0: findings.append(make_finding(business_id,'payment_mismatch','high',92,f'Payment shortfall for {o["entity_id"]}',f'Expected ₹{o["amount"]:,.2f}; recorded payment is ₹{payments[oid]["amount"]:,.2f}.',o['entity_id'],diff,95,['Order and payment IDs match','Amounts disagree'],'Verify the payment and follow up on the outstanding amount.'))
        c.execute('DELETE FROM findings WHERE business_id=? AND status="open"',(business_id,))
        for f in findings: c.execute('INSERT OR IGNORE INTO findings VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(f.id,f.business_id,f.kind,f.severity,f.priority,f.title,f.message,f.entity_id,f.impact,f.confidence,json.dumps(f.reasons),f.recommended_action,f.status,datetime.utcnow().isoformat()))
        c.execute('INSERT INTO audit(business_id,event,details,created_at) VALUES(?,?,?,?)',(business_id,'analysis',json.dumps({'findings':len(findings)}),datetime.utcnow().isoformat()))
    return findings

def make_finding(bid,kind,severity,priority,title,message,entity,impact,conf,reasons,action):
    raw=f'{bid}|{kind}|{entity}|{title}|{message}'; return Finding(hashlib.sha256(raw.encode()).hexdigest()[:16],bid,kind,severity,priority,title,message,entity,round(float(impact or 0),2),int(conf),reasons,action)

def seed_demo():
    ensure_business('demo','Demo Retailer')
    sample=[{'record_id':'ORD-1001','type':'order','customer':'Rahul Traders','amount':'12000','date':'2026-09-12'},{'record_id':'PAY-1001','type':'payment','order_id':'ORD-1001','payment':'10000','date':'2026-09-12'},{'record_id':'INV-2001','type':'invoice','customer':'ABC Store','amount':'8500','date':'2026-09-12'},{'record_id':'INV-2001','type':'invoice','customer':'ABC Store','amount':'6500','date':'2026-09-12'},{'record_id':'ORD-1002','type':'order','customer':'Good Foods','amount':'4500','date':'2026-09-12'}]
    (INBOX/'demo.csv').write_text('record_id,type,customer,amount,date,order_id,payment\n'+'\n'.join(','.join(str(x.get(k,'')) for k in ['record_id','type','customer','amount','date','order_id','payment']) for x in sample)+'\n',encoding='utf-8'); return ingest('demo')

def dashboard_data(bid='demo'):
    with db() as c:
        b=c.execute('SELECT * FROM businesses WHERE id=?',(bid,)).fetchone(); rec=c.execute('SELECT * FROM records WHERE business_id=? ORDER BY id DESC',(bid,)).fetchall(); fs=c.execute('SELECT * FROM findings WHERE business_id=? ORDER BY priority DESC, impact DESC',(bid,)).fetchall(); actions=c.execute('SELECT * FROM actions WHERE business_id=? ORDER BY created_at DESC',(bid,)).fetchall()
    return b,rec,fs,actions

def approve(finding_id,bid='demo'):
    with db() as c:
        f=c.execute('SELECT * FROM findings WHERE id=? AND business_id=?',(finding_id,bid)).fetchone()
        if not f: return False
        aid=hashlib.sha256(f'{finding_id}|action'.encode()).hexdigest()[:16]; c.execute('INSERT OR IGNORE INTO actions VALUES(?,?,?,?,?,?,?,?)',(aid,bid,finding_id,'review_and_resolve',f['recommended_action'],'approved',datetime.utcnow().isoformat(),None)); c.execute('UPDATE findings SET status="acknowledged" WHERE id=?',(finding_id,)); c.execute('INSERT INTO audit(business_id,event,details,created_at) VALUES(?,?,?,?)',(bid,'action_approved',json.dumps({'finding_id':finding_id,'action_id':aid}),datetime.utcnow().isoformat())); return True

def resolve(finding_id,bid='demo'):
    with db() as c:
        cur=c.execute('UPDATE findings SET status="resolved" WHERE id=? AND business_id=?',(finding_id,bid)); c.execute('INSERT INTO audit(business_id,event,details,created_at) VALUES(?,?,?,?)',(bid,'finding_resolved',json.dumps({'finding_id':finding_id}),datetime.utcnow().isoformat())); return cur.rowcount>0

init_db()
