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
  streamView.style.display = (v==='stream')?'flex':'none';
  aggView.style.display = (v==='agg')?'flex':'none';
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
  if(!confirm('Clear all logs?')) return;
  await fetch('/api/v1/logs', {method:'DELETE'});
  streamBody.innerHTML=''; allItems.length=0; renderAgg();
};
autoRefreshEl.addEventListener('change', function(){
  LIVE = autoRefreshEl.checked;
  localStorage.setItem('autoRefresh', JSON.stringify(LIVE));
  if (LIVE) connectSSE(); else disconnectSSE();
});

/* --- helpers --- */
function esc(s){
  if(s===null||s===undefined) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}
function rel(t){var d=Date.now()-new Date(t).getTime();if(!isFinite(d))return'';var s=Math.floor(d/1000);if(s<60)return s+'s';var m=Math.floor(s/60);if(m<60)return m+'m';var h=Math.floor(m/60);if(h<24)return h+'h';return Math.floor(h/24)+'d';}
function norm(it){try{ if(it && typeof it.fields==='string' && it.fields && it.fields!=='null'){ it.fields=JSON.parse(it.fields);} }catch(e){} return it;}
function getAction(it){return (it && (it.action || (it.fields&&it.fields.action) || '')).toString().toUpperCase();}
function getComp(it){return (it && (it.component || (it.fields&&it.fields.component) || '')).toString().toLowerCase();}
function hostOf(it){var f=(it&&it.fields)||{};return it.http_host||it.host||it.sni||it.qname||f.http_host||f.host||f.sni||f.qname||'';}
function dstOf(it){if(it&&it.dst)return it.dst; if(it&&it.destination_ip&&it.destination_port)return it.destination_ip+':'+it.destination_port; return it&&it.destination_ip?it.destination_ip:'';}
function srcOf(it){if(it&&it.src)return it.src; if(it&&it.source_ip&&it.source_port)return it.source_ip+':'+it.source_port; return it&&it.source_ip?it.source_ip:'';}
function hostnameOf(it){return it.hostname || ((it.fields&&it.fields.hostname)||'');}
function flowIdOf(it){return it.flow_id || ((it.fields&&it.fields.flow_id)||'');}
function versionOf(it){return it.version || ((it.fields&&it.fields.version)||'');}

/* filter */
function matches(it){
  var aSel=(actionEl.value||'').toUpperCase();
  var cSel=(compEl.value||'').toLowerCase();
  var q=(searchEl.value||'').toLowerCase();
  var act=getAction(it); if(aSel && act!==aSel) return false;
  var comp=getComp(it); if(cSel && comp!==cSel) return false;
  if(!q) return true;
  var hay=[act, comp, hostOf(it), srcOf(it), dstOf(it), hostnameOf(it), flowIdOf(it), versionOf(it)].join(' ').toLowerCase();
  return hay.indexOf(q)!==-1;
}

/* --- stream --- */
var allItems=[];
function rowHTML(it){
  var act  = getAction(it);
  var comp = getComp(it) || (it.component||'');
  var host = hostOf(it);
  var src  = srcOf(it);
  var dst  = dstOf(it);
  var hn   = hostnameOf(it);
  var fid  = flowIdOf(it);
  var ver  = versionOf(it);
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
    '<td class="mono">'+esc(ver)+'</td>' +
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
  var res = await fetch('/api/v1/logs?limit=500');
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
  es = new EventSource('/api/v1/events');
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
