// Run with Node and Playwright available (NODE_PATH may point to bundled packages).
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const assert = require('assert');
(async () => {
  const source = fs.readFileSync(path.join(__dirname, '../factory/dashboard.html'), 'utf8');
  const utils = source.slice(source.indexOf('const domChildren ='), source.indexOf('const ms ='));
  const render = source.slice(source.indexOf('function renderDeployments()'), source.indexOf('function renderStatus()'));
  const states = ['pending','executing','verifying','failed','interrupted','superseded','succeeded'];
  const data = { targets: [{target:'default'},{target:'other'}], metrics: {
    recorded_attempts:7, successes:1, failures:1,success_denominator:2,mean_execution_sec:1,
    duration_denominator:2,mean_queue_sec:2,queue_denominator:2},history:{truncated:false},
    runs:states.map((status,i) => ({run_id:'fixture-'+status,target:i===6?'other':'default',
      ticket:i+1,commit:'a'.repeat(40),status,unresolved:status==='failed',started_at:'now',
      timeline:[{at:'now',status,phase:status}],verification:{verdict:status},result:null,
      publication:{pr:{status:'ok'}},artifacts:[{name:'apply.log',url:'/api/artifacts/default/fixture/apply.log'}]}))};
  const browser = await chromium.launch({headless:true, ...(process.env.BROWSER_CHANNEL ? {channel:process.env.BROWSER_CHANNEL} : {})});
  try {
    const page = await browser.newPage({viewport:{width:1100,height:800}});
    const errors=[];page.on('pageerror',e=>errors.push(e.message));
    await page.route('http://fixture.local/**',route=>route.fulfill({status:200,contentType:'text/plain',body:'safe log <script>throw new Error("injected")</script>'}));
    await page.goto('http://fixture.local/');
    await page.setContent('<select id="deploy-target"></select><select id="deploy-status"><option value="">All</option>'+states.map(s=>`<option>${s}</option>`).join('')+'</select><div id="deploy-metrics"></div><div id="deployments"></div>');
    await page.addScriptTag({content:`const $ = id => document.getElementById(id); const S = {snap:{deployments:${JSON.stringify(data)}}}; ${utils}\n${render}\nrenderDeployments();`});
    assert.equal(await page.locator('.deployment-run').count(),7);
    for(const state of states) assert.equal(await page.locator(`[data-state="${state}"]`).count(),1);
    await page.selectOption('#deploy-status','failed');
    assert.equal(await page.locator('.deployment-run').count(),1);
    await page.locator('summary').click();
    await page.getByRole('button',{name:'View apply.log'}).click();
    await page.waitForFunction(()=>document.querySelector('#deployments').textContent.includes('safe log <script>'));
    await page.evaluate(() => renderDeployments());
    assert.equal(await page.locator('.deployment-run').evaluate(el => el.open), true);
    assert.ok((await page.locator('#deployments').textContent()).includes('safe log <script>'));
    await page.selectOption('#deploy-status','');
    await page.selectOption('#deploy-target','other');
    assert.equal(await page.locator('.deployment-run').count(),1);
    assert.equal(await page.locator('.deployment-run').getAttribute('data-state'),'succeeded');
    assert.deepEqual(errors,[]);
    if(process.env.SCREENSHOT) await page.screenshot({path:process.env.SCREENSHOT,fullPage:true});
    console.log('PASS: seven deployment states, filters, artifact viewer and text safety');
  } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exit(1);});
