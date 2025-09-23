package dashboard

import (
	"net/http"
	"time"
)

// IndexHandler serves the embedded dashboard HTML/JS/CSS.
//
//nolint:funlen,lll
func IndexHandler(_ time.Duration) http.Handler {
	const page = `<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<title>g0efilter dashboard</title>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<style>
:root{
  --bg:#0b0f14;--panel:#0d1220;--border:#1c2433;--text:#e5e7eb;--muted:#9ca3af;
  --ok:#10b981;--warn:#f59e0b;--err:#ef4444;--chip:#111827;--chip2:#1f2937;
}
*{box-sizing:border-box}
html,body{height:100%}
body{
  margin:0;background:var(--bg);color:var(--text);
  font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Inter,Arial,sans-serif;
  display:flex;flex-direction:column;min-height:0
}
header{
  flex:0 0 auto;position:sticky;top:0;z-index:10;padding:10px 14px;
  background:#111827;border-bottom:1px solid var(--border);
  display:flex;gap:12px;align-items:center;flex-wrap:wrap
}
header h1{margin:0;font-size:16px}
.controls{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.controls select,input,button{background:#0f172a;border:1px solid var(--border);color:var(--text);border-radius:8px;padding:6px 8px;font-size:12px}
button{cursor:pointer}
button.primary{background:#1e293b}
.tabs{display:flex;gap:6px;margin-left:auto}
.tab{padding:6px 10px;border:1px solid var(--border);border-radius:999px;background:#0f172a;font-size:12px;cursor:pointer}
.tab.active{background:#1e293b}

main{flex:1 1 auto;display:flex;flex-direction:column;min-height:0;padding:10px 12px}
.box{
  background:var(--panel);border:1px solid var(--border);border-radius:10px;
  padding:10px;display:flex;flex-direction:column;min-height:0;height:100%
}
#streamView,#aggView{flex:1 1 auto;display:flex;min-height:0}
#streamBox,#aggBox{flex:1 1 auto;display:flex;flex-direction:column;min-height:0;overflow:auto}

/* Tables */
.table{width:100%;border-collapse:separate;border-spacing:0;table-layout:fixed;font-variant-numeric:tabular-nums}
.table th,.table td{
  padding:6px 8px;border-bottom:1px solid var(--border);
  font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0
}
.table th{
  color:#cbd5e1;font-weight:600;background:#0f172a;position:sticky;top:0;z-index:5;
  text-align:left; /* ← add this */
}
.mono{font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace}

/* Badges */
.badge{display:inline-block;border-radius:999px;padding:2px 6px;font-size:11px;border:1px solid var(--border)}
.badge-ALLOWED{background:rgba(16,185,129,.15);color:#d1fae5;border-color:rgba(16,185,129,.35)}
.badge-BLOCKED{background:rgba(239,68,68,.15);color:#fee2e2;border-color:rgba(239,68,68,.35)}
.badge-REDIRECTED{background:rgba(245,158,11,.15);color:#fef3c7;border-color:rgba(245,158,11,.35)}
.badge-INFO{background:#1f2937;color:#cbd5e1}

small{color:var(--muted);font-size:11px}
#connectionStatus{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--ok);margin-left:4px}
#connectionStatus.disconnected{background:var(--err)}

input[type="search"]{min-width:220px}
</style>
</head>
<body>
<header>
  <h1>g0efilter</h1>
  <div class="controls">
    <label><input type="checkbox" id="autoRefresh"/> Live <span id="connectionStatus"></span></label>
    <label>Action
      <select id="actionFilter">
        <option value="">All</option>
        <option value="ALLOWED">ALLOWED</option>
        <option value="BLOCKED">BLOCKED</option>
        <option value="REDIRECTED">REDIRECTED</option>
      </select>
    </label>
    <label>Component
      <select id="componentFilter">
        <option value="">Any</option>
        <option value="sni">sni</option>
        <option value="http">http</option>
        <option value="dns">dns</option>
      </select>
    </label>
    <input id="search" type="search" placeholder="Search host/SNI/src/dst/flow_id/hostname…" />
    <button id="apply" class="primary">Apply</button>
    <input id="apiKey" placeholder="API key (for clear)" size="16" type="password"/>
    <button id="clearBtn" title="requires API key">Clear</button>
  </div>
  <div class="tabs">
    <button class="tab active" id="tabStream">Stream</button>
    <button class="tab" id="tabAgg">Aggregates</button>
  </div>
</header>

<main>
  <!-- Stream -->
  <section id="streamView">
    <div id="streamBox" class="box">
      <table class="table">
        <colgroup>
          <col style="width:110px">  <!-- Action -->
          <col style="width:84px">   <!-- Comp -->
          <col style="width:300px">  <!-- Host/SNI -->
          <col style="width:220px">  <!-- Src -->
          <col style="width:240px">  <!-- Dst -->
          <col style="width:180px">  <!-- Hostname -->
          <col style="width:120px">  <!-- Flow ID -->
          <col style="width:200px">  <!-- Time -->
        </colgroup>
        <thead>
          <tr>
            <th>Action</th>
            <th>Comp</th>
            <th>Host/SNI</th>
            <th>Src</th>
            <th>Dst</th>
            <th>Hostname</th>
            <th>Flow ID</th>
            <th>Time</th>
          </tr>
        </thead>
        <tbody id="streamBody"></tbody>
      </table>
    </div>
  </section>

  <!-- Aggregates (simplified) -->
  <section id="aggView" style="display:none">
    <div id="aggBox" class="box">
      <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:8px">
        <small id="aggStats"></small>
        <button id="aggRefresh" class="primary">Refresh</button>
      </div>
      <table class="table">
      <colgroup>
        <col>                       <!-- Key -->
        <col style="width:100px">   <!-- Total -->
        <col style="width:120px">   <!-- Action -->
        <col style="width:220px">   <!-- Last Seen -->
      </colgroup>
      <thead>
        <tr>
          <th style="text-align:left">Key (SNI/Host/IP)</th>
          <th>Total</th>
          <th>Action</th>
          <th>Last Seen</th>
        </tr>
      </thead>
        <tbody id="aggBody"></tbody>
      </table>
    </div>
  </section>
</main>

<script>
/* --- state --- */
var LIVE = JSON.parse(localStorage.getItem('autoRefresh') || 'true');
var VIEW = localStorage.getItem('view') || 'stream';
var MAX_ROWS = 2000;

/* elements */
var autoRefreshEl = document.getElementById('autoRefresh');
var actionEl = document.getElementById('actionFilter');
var compEl = document.getElementById('componentFilter');
var searchEl = document.getElementById('search');
var streamBody = document.getElementById('streamBody');
var connectionStatus = document.getElementById('connectionStatus');
var tabStream = document.getElementById('tabStream');
var tabAgg = document.getElementById('tabAgg');
var streamView = document.getElementById('streamView');
var aggView = document.getElementById('aggView');
var aggBody = document.getElementById('aggBody');
var aggStats = document.getElementById('aggStats');
var apiKeyEl = document.getElementById('apiKey');

/* persistence + tab init */
autoRefreshEl.checked = LIVE;
function setView(v){
  VIEW = v; localStorage.setItem('view', v);
  tabStream.classList.toggle('active', v==='stream');
  tabAgg.classList.toggle('active', v==='agg');
  streamView.style.display = (v==='stream')?'block':'none';
  aggView.style.display = (v==='agg')?'block':'none';
}
setView(VIEW);
tabStream.onclick = function(){
  setView('stream');
  reload();               // refresh/backfill on tab switch
};
tabAgg.onclick = function(){
  setView('agg');
  reload();               // refresh/backfill on tab switch
};

/* controls */
document.getElementById('apply').onclick = function(){ renderStream(true); if(VIEW==='agg') renderAgg(); };
document.getElementById('clearBtn').onclick = async function(){
  var key = (apiKeyEl.value||'').trim();
  if(!key){ alert('Enter API key'); return; }
  if(!confirm('Clear all logs?')) return;
  await fetch('/logs/clear', {method:'POST', headers:{'X-Api-Key': key}});
  streamBody.innerHTML=''; allItems.length=0; renderAgg();
};
autoRefreshEl.addEventListener('change', function(){
  LIVE = autoRefreshEl.checked;
  localStorage.setItem('autoRefresh', JSON.stringify(LIVE));
  if (LIVE) connectSSE(); else disconnectSSE();
});

/* --- helpers --- */
function esc(s){return (s==null?'':String(s)).replace(/[&<>]/g,function(m){return {'&':'&amp;','<':'&lt;','>':'&gt;'}[m]||m;});}
function rel(t){var d=Date.now()-new Date(t).getTime();if(!isFinite(d))return'';var s=Math.floor(d/1000);if(s<60)return s+'s';var m=Math.floor(s/60);if(m<60)return m+'m';var h=Math.floor(m/60);if(h<24)return h+'h';return Math.floor(h/24)+'d';}
function norm(it){try{ if(it && typeof it.fields==='string' && it.fields && it.fields!=='null'){ it.fields=JSON.parse(it.fields);} }catch(e){} return it;}
function getAction(it){return (it && (it.action || (it.fields&&it.fields.action) || '')).toString().toUpperCase();}
function getComp(it){return (it && (it.component || (it.fields&&it.fields.component) || '')).toString().toLowerCase();}
function hostOf(it){var f=(it&&it.fields)||{};return it.http_host||it.host||it.sni||it.qname||f.http_host||f.host||f.sni||f.qname||'';}
function dstOf(it){if(it&&it.dst)return it.dst; if(it&&it.destination_ip&&it.destination_port)return it.destination_ip+':'+it.destination_port; return it&&it.destination_ip?it.destination_ip:'';}
function srcOf(it){if(it&&it.src)return it.src; if(it&&it.source_ip&&it.source_port)return it.source_ip+':'+it.source_port; return it&&it.source_ip?it.source_ip:'';}
function hostnameOf(it){return it.hostname || ((it.fields&&it.fields.hostname)||'');}
function flowIdOf(it){return it.flow_id || ((it.fields&&it.fields.flow_id)||'');}

/* filter */
function matches(it){
  var aSel=(actionEl.value||'').toUpperCase();
  var cSel=(compEl.value||'').toLowerCase();
  var q=(searchEl.value||'').toLowerCase();
  var act=getAction(it); if(aSel && act!==aSel) return false;
  var comp=getComp(it); if(cSel && comp!==cSel) return false;
  if(!q) return true;
  var hay=[act, comp, hostOf(it), srcOf(it), dstOf(it), hostnameOf(it), flowIdOf(it)].join(' ').toLowerCase();
  return hay.indexOf(q)!==-1;
}

/* --- stream --- */
var allItems=[];
function rowHTML(it){
  var act  = getAction(it) || 'INFO';
  var comp = getComp(it) || (it.component||'');
  var host = hostOf(it);
  var src  = srcOf(it);
  var dst  = dstOf(it);
  var hn   = hostnameOf(it);
  var fid  = flowIdOf(it);
  var when = it.time || it.ts || new Date().toISOString();
  var badge = 'badge-'+act;
  return '<tr>' +
    '<td><span class="badge '+badge+'">'+esc(act)+'</span></td>' +
    '<td>'+esc(comp)+'</td>' +
    '<td>'+esc(host)+'</td>' +
    '<td class="mono">'+esc(src)+'</td>' +
    '<td class="mono">'+esc(dst)+'</td>' +
    '<td>'+esc(hn)+'</td>' +
    '<td class="mono">'+esc(fid)+'</td>' +
    '<td><small>'+esc(new Date(when).toLocaleString())+' <span style="opacity:.6">('+esc(rel(when))+' ago)</span></small></td>' +
  '</tr>';
}
function renderStream(replace){
  var out='';
  for(var i=0;i<allItems.length;i++){
    var it=allItems[i];
    if(!matches(it)) continue;
    out+=rowHTML(it);
  }
  if(replace){ streamBody.innerHTML=out; } else if(out){ streamBody.insertAdjacentHTML('afterbegin', out); }
}

/* --- aggregates (simplified) --- */
function renderAgg(){
  // key -> { total, lastSeen }
  var map=new Map();

  function keyFor(it){
    // Prefer SNI/Host, then DNS name, else destination(IP:port) or IP
    var key = hostOf(it);
    if(!key) key = dstOf(it);
    return key || '';
  }

  for(var i=0;i<allItems.length;i++){
    var it=allItems[i]; if(!matches(it)) continue;
    var key=keyFor(it); if(!key) continue;
    var rec = map.get(key);
    if(!rec){ rec={ total:0, lastSeen:0 }; map.set(key, rec); }
    rec.total++;
    var t=new Date(it.time||it.ts||Date.now()).getTime();
    if(t>rec.lastSeen) rec.lastSeen=t;
  }

  var rows=[];
  map.forEach(function(v,k){ rows.push({key:k,total:v.total,lastSeen:v.lastSeen}); });

  // Sort by total desc, then lastSeen desc
  rows.sort(function(a,b){ return (b.total-a.total) || (b.lastSeen-a.lastSeen); });

  var html='';
  for(var r=0;r<rows.length;r++){
    var a=rows[r];
    // pick the "dominant" action for this key: whichever had most hits
    var act = '';
    var actCounts = {ALLOWED:0, BLOCKED:0, REDIRECTED:0};
    for(var i=0;i<allItems.length;i++){
      var it=allItems[i];
      if(!matches(it)) continue;
      var key=hostOf(it)||dstOf(it)||'';
      if(key!==a.key) continue;
      var action = getAction(it);
      if(actCounts[action]!==undefined){ actCounts[action]++; }
    }
    var max=0;
    for(var k in actCounts){ if(actCounts[k]>max){ max=actCounts[k]; act=k; } }

    html+='<tr>'+
      '<td style="text-align:left">'+esc(a.key)+'</td>'+
      '<td>'+a.total+'</td>'+
      '<td>'+esc(act||'-')+'</td>'+
      '<td>'+(a.lastSeen? esc(new Date(a.lastSeen).toLocaleString())+' <span style="opacity:.6">('+esc(rel(a.lastSeen))+' ago)</span>':'')+'</td>'+
    '</tr>';
  }

  aggBody.innerHTML=html;
  aggStats.textContent=rows.length+' keys';
}
document.getElementById('aggRefresh').onclick=function(){ renderAgg(); };

/* --- data load (backfill from memory store) --- */
async function reload(){
  var res = await fetch('/logs?limit=500');
  var items = await res.json();
  for(var i=0;i<items.length;i++) items[i]=norm(items[i]);
  allItems = items;
  renderStream(true);
  renderAgg();
}

/* --- SSE --- */
var es=null;
function connectSSE(){
  disconnectSSE();
  es = new EventSource('/events');
  es.onmessage = function(ev){
    try{
      var it = JSON.parse(ev.data);
      if(it && it.type==='cleared'){
        streamBody.innerHTML=''; allItems.length=0; renderAgg(); return;
      }
      it = norm(it);
      allItems.unshift(it);
      if(allItems.length>MAX_ROWS) allItems.pop();
      if(VIEW==='stream' && matches(it)){
        streamBody.insertAdjacentHTML('afterbegin', rowHTML(it));
      }
      if(VIEW==='agg') renderAgg();
    }catch(e){}
  };
  es.onerror = function(){
    if(LIVE){
      connectionStatus.classList.add('disconnected');
      // EventSource auto-retries using server "retry:" hint
    }
  };
  es.onopen = function(){
    connectionStatus.classList.remove('disconnected');
  };
}
function disconnectSSE(){ if(es){ es.close(); es=null; } }

/* init */
reload().then(function(){ if(LIVE) connectSSE(); });
</script>
</body>
</html>`

	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page))
	})
}
