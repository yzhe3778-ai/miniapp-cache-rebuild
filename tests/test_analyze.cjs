'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { analyzeEvidence } = require('../scripts/analyze.cjs');
const sha = x => crypto.createHash('sha256').update(x).digest('hex');
function fixture(t, files, packages = null) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'miniapp-analyzer-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const records = [];
  for (const [relative, code] of Object.entries(files)) {
    const bytes = Buffer.from(code), target = path.join(root, 'packages/main/files', relative);
    fs.mkdirSync(path.dirname(target), { recursive: true }); fs.writeFileSync(target, bytes);
    records.push({ relative_path: relative, path: '/' + relative, size: bytes.length, sha256: sha(bytes) });
  }
  const manifest = { schema: 2, appid: 'wx0000000000000000', packages: packages ?? [{ name: '__APP__.wxapkg', status: 'verified', version_directory: '1', extracted_directory: 'packages/main/files', files: records }] };
  fs.writeFileSync(path.join(root, 'package-manifest.json'), JSON.stringify(manifest));
  return { root, records, manifest, analyze: () => analyzeEvidence(root, '1') };
}
function config(result, name, module = null) { return result.configExpressions.find(c => c.name === name && (module === null || c.module === module)); }
test('unknown target calls are never executed', t => {
  const marker = path.join(os.tmpdir(), 'miniapp-must-not-execute-' + process.pid);
  fs.rmSync(marker, { force: true });
  const f = fixture(t, { 'app-service.js': `const payload = require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'bad'); const list = ['safe'];` });
  const result = f.analyze(); assert.equal(fs.existsSync(marker), false); assert.deepEqual(config(result, 'list').value, ['safe']);
});
test('tracks final dynamic arrays, static helpers, push.apply and concat', t => {
  const f = fixture(t, { 'app-service.js': `define('templates.js', function(require) { var spread=require('@babel/runtime/helpers/toConsumableArray'); var templates=[{id:1}]; templates.push({id:2}); templates.push.apply(templates,[{id:3}]); templates=templates.concat(spread([{id:4}])); });` });
  const c = config(f.analyze(), 'templates'); assert.equal(c.finalLength, 4); assert.deepEqual(c.value.map(v => v.id), [1, 2, 3, 4]); assert.equal(c.history.length, 4);
});
test('safe pure map/flatMap expands API integration prompt', t => {
  const f = fixture(t, { 'app-service.js': `define('docs.js', function() { const endpoints=Object.freeze([{path:'/overview',method:'GET'},{path:'/status',method:'GET'}]); const lines=endpoints.flatMap((entry,index)=>[StringNotAllowed(), entry.path]); const safe=endpoints.flatMap(function(e,i){return [''.concat(i+1,':').concat(e.path), e.method];}); const prompt=['请接入 API 契约，鉴权规则如下。'].concat(safe,['请使用接口约定，并遵守接口权限要求。'.repeat(2)]).join('\\n'); const expanded=['API 接入契约，请使用以下鉴权与接口规则。xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'].concat(safe).join('\\n'); });` });
  const result = f.analyze(); assert.deepEqual(config(result, 'safe').value, ['1:/overview', 'GET', '2:/status', 'GET']); assert.equal(config(result, 'lines').value[0].unresolved, 'call-not-allowlisted'); assert.match(config(result, 'expanded').value, /1:\/overview/);
});
test('lexical shadowing never merges values by identifier spelling', t => {
  const f = fixture(t, { 'app-service.js': `const base='https://outer.example'; function other(){const base='https://inner.example'; wx.request({url:base+'/inner',method:'POST',header:{Authorization:'private',Accept:'application/json'},data:{vote:true}});} wx.request({url:base+'/outer',method:'GET'});` });
  const result = f.analyze(), requests = result.endpoints.filter(x => x.evidence === 'client-request-call'); assert.deepEqual(requests.map(x => x.url), ['https://inner.example/inner', 'https://outer.example/outer']); assert.deepEqual(requests[0].headerNames, ['Authorization', 'Accept']); assert.deepEqual(requests[0].inputFieldNames, ['vote']);
});
test('module namespace+hash dedup preserves duplicates and conflicts', t => {
  const f = fixture(t, { 'a.js': `define('same.js',function(){const a=[1];});`, 'b.js': `define('same.js',function(){const a=[1];}); define('same.js',function(){const a=[2];});` });
  const result = f.analyze(); assert.equal(result.modules.length, 2); assert.equal(result.moduleConflicts.length, 1); assert.equal(result.modules.find(x => x.sources.length === 2).sources.length, 2);
});
test('styles retain tokens/raw and explicitly warn missing imports and unknown tokens', t => {
  const f = fixture(t, { 'app-wxss.js': `__COMMON_STYLESHEETS__['shared.wxss']=['.shared{width:',[0,20],';}']; __wxAppCode__['pages/home.wxss']=setCssToHead(['wx-view{padding:',[0,16],';}',[2,'./shared.wxss'],[2,'./missing.wxss'],[7,42],[1,'scope']]);` });
  const result = f.analyze(); assert.equal(result.styles.length, 2); assert.ok(result.warnings.some(x => x.code === 'missing-style-import')); assert.ok(result.warnings.some(x => x.code === 'unknown-style-token')); const style = result.styles.find(x => x.kind === 'page'); const css = fs.readFileSync(path.join(f.root, 'analysis/1', style.browserFile), 'utf8'); assert.match(css, /div\{padding:calc\(var\(--rpx\) \* 16\)/); assert.match(css, /\.shared/); assert.match(fs.readFileSync(path.join(f.root, 'analysis/1', style.rawFile), 'utf8'), /16rpx/);
});
test('rejects traversal manifest paths before reading target', t => {
  const f = fixture(t, { 'app-service.js': 'const a=[1];' }); f.manifest.packages[0].files[0].relative_path = '../secret.js'; fs.writeFileSync(path.join(f.root, 'package-manifest.json'), JSON.stringify(f.manifest)); assert.throws(f.analyze, /Unsafe relative path/);
});
test('rejects altered hashes and symlink evidence', t => {
  const f = fixture(t, { 'app-service.js': 'const a=[1];' }); fs.writeFileSync(path.join(f.root, 'packages/main/files/app-service.js'), 'changed'); assert.throws(f.analyze, /SHA256 mismatch/); fs.unlinkSync(path.join(f.root, 'packages/main/files/app-service.js')); fs.symlinkSync(path.join(f.root, 'package-manifest.json'), path.join(f.root, 'packages/main/files/app-service.js')); assert.throws(f.analyze, /Symlink/);
});
test('refuses arbitrary callback statements and never executes them', t => {
  const f = fixture(t, { 'app-service.js': 'const original=[1,2]; const mapped=original.map(x=>{ console.log("bad"); return x; }); const good=original.map(x=>({id:x+1}));' }); const result = f.analyze(); assert.equal(config(result, 'mapped').finalLength, 2); assert.match(config(result, 'mapped').value[0].unresolved, /map-shape-only/); assert.deepEqual(config(result, 'good').value, [{id:2},{id:3}]);
});
test('client timers carry callback evidence without backend/realtime claims', t => {
  const f = fixture(t, { 'app-service.js': 'setInterval(function(){ updateClock(); },60000); setTimeout(showPoint,650);' }); const result = f.analyze(); assert.deepEqual(result.timers.map(x => x.intervalMilliseconds), [60000,650]); assert.match(result.timers[0].callbackExpression, /updateClock/); assert.match(result.timers[0].meaning, /not inferred/);
});
test('explicit selected version is mandatory and unverified packages are not read', t => {
  const f = fixture(t, {}, [{name:'missing',status:'failed',version_directory:'1',extracted_directory:'../../private',files:[]}]); const result = f.analyze(); assert.equal(result.coverage.verifiedPackages,0); assert.ok(result.warnings.some(x=>x.code==='unverified-package-skipped')); assert.throws(()=>analyzeEvidence(f.root,'2'),/No packages match/);
});
test('conditional mutation invalidates final static count instead of reporting old count', t => {
  const f = fixture(t, { 'app-service.js': 'const templates=[1]; if(userPermission){templates.push(2);} const after=templates;' }); const result = f.analyze(); const item = config(result,'templates'); assert.equal(item.finalLength,null); assert.equal(item.value.unresolved,'conditional-or-cross-function-mutation');
});
test('dangling output symlink is rejected without creating its target', t => {
  const f = fixture(t, { 'app-service.js':'const data=[1];' }); const output=path.join(f.root,'output');fs.mkdirSync(output);const missing=path.join(f.root,'should-not-create.json');fs.symlinkSync(missing,path.join(output,'analysis.json'));assert.throws(()=>analyzeEvidence(f.root,'1',output),/Symlink/);assert.equal(fs.existsSync(missing),false);
});
test('unresolved requests preserve expressions and static prompt purpose stays unverified', t => {
 const f=fixture(t,{'app-service.js':'const prompt="请分析这些内容。xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"; wx.request({url:unknownBase+"/history",method:"GET"});'});const result=f.analyze();assert.equal(result.prompts[0].kind,'actual-static-text');assert.equal(result.prompts[0].purpose,'unverified');assert.equal(result.endpoints.find(x=>x.evidence==='client-request-call').url.unresolved,'unresolved-binary-left');
});
test('a shadowed require cannot impersonate Babel array helper', t => {
 const f=fixture(t,{'app-service.js':"function require(name){return ()=>[999];} const helper=require('@babel/runtime/helpers/toConsumableArray'); const items=helper([1,2]);"});assert.equal(config(f.analyze(),'items'),undefined);
});
test('compiler registration guard does not invalidate static factory-local configuration', t => {
 const f=fixture(t,{'app-service.js':"if(typeof runtime!=='undefined'){define('data.js',function(){const items=[1,2];items.push(3);});}"});assert.equal(config(f.analyze(),'items').finalLength,3);
});
test('for initializer has a known literal array but dynamic loop writes remain unresolved', t => {
 const f=fixture(t,{'app-service.js':'for(var table={},i=0,ids=[1,2,3];i<ids.length;i++){table[ids[i]]={id:ids[i]};}'});const result=f.analyze();assert.equal(config(result,'ids').finalLength,3);assert.equal(config(result,'table').value.unresolved,'dynamic-or-conditional-member-mutation');
});
test('indexes storage export navigation and state syntax with handler provenance', t => {
 const f=fixture(t,{'app-service.js':"define('pages/home.js',function(){Page({saveSchedule(){wx.setStorageSync('schedule',[]);this.setData({saved:true});wx.canvasToTempFilePath({});wx.navigateTo({url:'/preview'});}});});"});
 const rows=f.analyze().behaviors;
 assert.deepEqual(rows.map(r=>r.kind),['storage','state','export','navigation']);
 assert.ok(rows.every(r=>r.owner==='saveSchedule'&&r.module==='pages/home.js'&&r.source.line===1));
 assert.ok(rows.every(r=>r.evidence==='static-call-syntax'));
});
test('shadowed wx and callback spelling stay unverified static candidates', t => {
 const f=fixture(t,{'app-service.js':"function fake(wx){wx.setStorageSync('schedule',[]);} const exportFile=()=>wx.saveFile({success:function done(){this.setData({ok:true});}});"});
 const rows=f.analyze().behaviors;
 assert.deepEqual(rows.map(r=>r.owner),['fake','done','exportFile']);
 assert.ok(rows.every(r=>/does not prove/.test(r.limitation)));
});
