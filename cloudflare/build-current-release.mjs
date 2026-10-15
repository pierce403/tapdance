import{readFileSync,cpSync,mkdirSync,writeFileSync}from'node:fs';
import{resolve}from'node:path';import{execFileSync}from'node:child_process';import{createHash}from'node:crypto';
const root=resolve(import.meta.dirname,'..');
const version=readFileSync(resolve(root,'VERSION'),'utf8').trim();
if(!/^\d+\.\d+\.\d+(?:[.-][A-Za-z0-9.-]+)?$/.test(version))throw Error('Invalid published version');
const output=resolve(root,'tmp/cloudflare-current-release');mkdirSync(output,{recursive:true});
cpSync(resolve(root,'site'),output,{recursive:true});
for(const name of ['tapdance.apk','tapdance.apk.sha256','tapdance.apk.cert-sha256']){
 execFileSync('curl',['-fsSL','--retry','3','--max-time','120','--proto','=https','--proto-redir','=https',
  'https://github.com/pierce403/tapdance/releases/download/v'+version+'/'+name,'-o',resolve(output,name)],{stdio:'inherit'});
}
const expected=readFileSync(resolve(output,'tapdance.apk.sha256'),'utf8').trim().match(/^([a-f0-9]{64})\s+\*?tapdance\.apk$/)?.[1];
const bytes=readFileSync(resolve(output,'tapdance.apk'));
if(!expected||createHash('sha256').update(bytes).digest('hex')!==expected)throw Error('Published APK checksum mismatch');
const signer=readFileSync(resolve(output,'tapdance.apk.cert-sha256'),'utf8').trim();
if(!/^[a-f0-9]{64}$/i.test(signer))throw Error('Published signer receipt invalid');
const release=await fetch('https://api.github.com/repos/pierce403/tapdance/releases/tags/v'+version,{headers:{Accept:'application/vnd.github+json'}});
if(!release.ok)throw Error('Published release metadata unavailable');
const metadata=await release.json();if(metadata.draft||metadata.tag_name!=='v'+version||!metadata.published_at)throw Error('Release is not published');
let html=readFileSync(resolve(output,'index.html'),'utf8');
for(const[key,value]of Object.entries({VERSION:version,BUILD_DATE:metadata.published_at.slice(0,10),APK_SHA256:expected,SIGNER_SHA256:signer}))html=html.replaceAll('__'+key+'__',value);
if(/__[A-Z0-9_]+__/.test(html))throw Error('Unresolved site token');
writeFileSync(resolve(output,'index.html'),html);writeFileSync(resolve(output,'.nojekyll'),'');
console.log(JSON.stringify({version,bytes:bytes.length,sha256:expected,signerReceipt:signer,existingRelease:true}));
