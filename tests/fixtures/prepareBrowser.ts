/** Explicitly invoked, disposable browser fixture. Never run against a production database. */
import assert from 'node:assert/strict';
import supertest from 'supertest';
import {createPool,migrate,list} from '../../server/db';
import {createUser} from '../../server/auth';
import {createApp} from '../../server/app';
import {loadConfig} from '../../server/config';
import {processPipeline} from '../../server/pipeline';
import {deliverNext} from '../../server/delivery';
import type {Finding,NormalizedCVE} from '../../src/types';
const config=loadConfig();
if(config.NODE_ENV!=='test' || !new URL(config.DATABASE_URL).pathname.endsWith('/vulnstream_pages')) throw new Error('Disposable vulnstream_pages test database required');
const pool=createPool(config.DATABASE_URL);
try {
await migrate(pool);
await createUser(pool,'pagecheck','Disposable-page-check-2026!','ADMIN');
const request=async()=>({status:200,body:'[]',headers:{}});
const app=createApp(pool,config,request),agent=supertest.agent(app);
const login=await agent.post('/api/login').set('Origin',config.APP_ORIGIN).send({username:'pagecheck',password:'Disposable-page-check-2026!'});
assert.equal(login.status,200);
const post=async(path:string,data:any)=>{const r=await agent.post(path).set('Origin',config.APP_ORIGIN).set('x-csrf-token',login.body.csrfToken).send(data);assert.ok(r.status<300,JSON.stringify(r.body));return r.body;};
const command=(action:string,data:any)=>post('/api/commands',{action,data});
const cpe=(version:string,product='widget',arch='*')=>`cpe:2.3:a:example:${product}:${version}:*:*:*:*:*:${arch}:*`;
for(const [tag,version,product,active] of [['AFFECTED','1.5','widget',true],['PATCHED','2.0','widget',true],['UNKNOWN','*','widget',true],['UNRELATED','1.5','other',true],['INACTIVE','1.5','widget',false]] as const){await command('asset.save',{vendor:'example',product,cpes:[cpe(version,product)],assetTag:tag,ownerGroup:'Browser verification',active});}
for(const [tag,version] of [['PACKAGE-AFFECTED','@1.5'],['PACKAGE-PATCHED','@2.0'],['PACKAGE-UNKNOWN','']] as const)await command('asset.save',{vendor:'example',product:'dependency',cpes:[],purls:['pkg:npm/dependency'+version],assetTag:tag,ownerGroup:'Browser verification',active:true});
const now=new Date().toISOString();
const cve:NormalizedCVE={cveId:'CVE-2026-90001',title:'TEST FIXTURE — Widget range',description:'Disposable browser verification fixture; not a real vulnerability advisory.',publishedDate:now,modifiedDate:now,cvss:{version:'3.1',score:8.1,vector:'',severity:'HIGH'},cwe:[],cpeMatches:[cpe('*')],versionRange:{versionStartIncluding:'1.0',versionEndExcluding:'2.0'},sourceFeeds:[],epss:{score:0.1,percentile:0.2},cisaKev:{isKev:false},exploitStatus:'None',remediation:{patchUrl:'',vendorAdvisoryRef:'',immediateActions:[],workarounds:[],rollbackPlan:'',stepByStep:[]}};
await command('cve.save',cve);
await command('cve.save',{...cve,cveId:'CVE-2026-90002',title:'TEST FIXTURE — Package range',cpeMatches:[],purls:['pkg:npm/dependency']});
await command('recipient.save',{name:'Test transport (no external messages)',email:'fixture@example.invalid',role:'Test',subscriptionTier:'ALL_SEVERITIES',enabled:true});
await command('feed.save',{name:'Disabled test JSON source',type:'JSON_SEARCH_API',url:'https://8.8.8.8/fixture',authType:'NONE',rateLimitPerMin:1,enabled:false});
await command('settings.save',{autoDispatchEnabled:true});
await post('/api/pipeline',{scopeHours:24});
await processPipeline(pool,config,request);
const findings=await list<Finding>(pool,'findings');
assert.deepEqual(findings.map(f=>f.matchedAssetName.split(' (')[0]).sort(),['AFFECTED','PACKAGE-AFFECTED','PACKAGE-UNKNOWN','UNKNOWN']);
assert.equal(findings.filter(f=>f.notificationStatus==='REVIEW_REQUIRED').length,2);
await deliverNext(pool,config,request,async()=> 'mock-browser-acceptance');
await post('/api/pipeline',{scopeHours:24});await processPipeline(pool,config,request);
assert.equal((await list(pool,'findings')).length,4);
assert.equal((await list(pool,'advisories')).length,1);
console.log('Persisted CPE/PURL matrix verified: 2 confirmed, 2 review, 4 excluded; rerun idempotent. Delivery transport mocked.');
} finally{await pool.end();}
