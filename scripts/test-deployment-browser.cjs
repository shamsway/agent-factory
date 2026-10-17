// Drives the real workspace assets (dashboard.html + workspace*.js) in Chromium with the
// JSON API stubbed: Deployments view states, filters, and safe artifact text display.
// Run with Node and Playwright available (NODE_PATH may point to bundled packages).
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const assert = require('assert');

const ROOT = path.join(__dirname, '../factory');
const ORIGIN = 'http://fixture.local:8765';
const REPOSITORY = 'acme/widgets';
const TYPES = {'.html':'text/html','.js':'text/javascript','.css':'text/css','.ttf':'font/ttf','.txt':'text/plain'};
const states = ['pending','executing','verifying','failed','interrupted','superseded','succeeded'];
const deployments = {
  targets:[{target:'default',last_succeeded_commit:null,unresolved_failures:1,unfinished:1,runner_lock_held:false},
           {target:'other',last_succeeded_commit:'b'.repeat(40),unresolved_failures:0,unfinished:0,runner_lock_held:false}],
  metrics:{recorded_attempts:7,successes:1,failures:1,success_denominator:2,success_rate:0.5,mean_execution_sec:1,
           duration_denominator:2,mean_queue_sec:2,queue_denominator:2,queue_scope:'PR merge to attempt start'},
  history:{total:7,shown:7,truncated:false},
  runs:states.map((status,i) => ({run_id:'fixture-'+status,target:i===6?'other':'default',ticket:i+1,pr:10+i,
    commit:'a'.repeat(40),attempt:1,status,outcome:status,unresolved:status==='failed',started_at:'2026-10-16T00:00:00Z',
    timeline:[{at:'2026-10-16T00:00:00Z',status,phase:status}],
    verification:{verdict:status==='succeeded'?'healthy':'unhealthy',elapsed_sec:3,timeout_sec:60,
                  items:[{kind:'check',name:'healthz',state:'healthy',detail:'first line\n<img src=x onerror=alert(1)>'}]},
    result:null,publication:{pr:{status:'ok'}},
    needs_attention:status==='succeeded',
    observations:status==='succeeded'?[{at:'2026-10-17T00:00:00Z',kind:'platform_pr',state:'closed',
      detail:'closed without merge <b>x</b>',url:'https://github.com/o/r/pull/9',attention:true,final:true}]:[],
    artifacts:[{name:'apply.log',url:'/api/artifacts?target=default&run=fixture-'+status+'&name=apply.log'},
               {name:'evil',url:'https://example.invalid/steal'}]}))
};

(async () => {
  const browser = await chromium.launch({headless:true, ...(process.env.BROWSER_CHANNEL ? {channel:process.env.BROWSER_CHANNEL} : {})});
  try {
    const page = await browser.newPage({viewport:{width:1280,height:900}});
    const errors = [], artifactRequests = [];
    page.on('pageerror', e => errors.push(e.message));
    page.on('dialog', d => { errors.push('dialog: ' + d.message()); d.dismiss(); });
    await page.route(ORIGIN + '/**', route => {
      const url = new URL(route.request().url());
      const json = value => route.fulfill({status:200, contentType:'application/json', body:JSON.stringify(value)});
      if (url.pathname === '/api/data') return json({observed_at:null, collection:{selected_repository:REPOSITORY},
        repositories:[{slug:REPOSITORY, root:'/fixture', collection:{}, errors:[]}]});
      if (url.pathname === '/api/snapshot') return json({repo:REPOSITORY, generated_at:'2026-10-16T00:00:00Z', deployments});
      if (url.pathname === '/api/artifacts') {
        artifactRequests.push({query:Object.fromEntries(url.searchParams), key:route.request().headers()['x-factory-access']});
        return route.fulfill({status:200, contentType:'text/plain', body:'safe log <script>throw new Error("injected")</script>'});
      }
      if (url.pathname.startsWith('/api/')) return json({});
      const file = path.join(ROOT, url.pathname === '/' ? 'dashboard.html' : url.pathname);
      if (!file.startsWith(ROOT) || !fs.existsSync(file)) return route.fulfill({status:404, body:''});
      return route.fulfill({status:200, contentType:TYPES[path.extname(file)] || 'application/octet-stream', body:fs.readFileSync(file)});
    });
    await page.goto(`${ORIGIN}/?view=deployments&repository=${encodeURIComponent(REPOSITORY)}#access=${'k'.repeat(40)}`);
    const runs = page.locator('details.deploy-run');
    await runs.first().waitFor();
    assert.equal(await runs.count(), 7);
    for (const state of states) assert.equal(await page.locator(`details.deploy-run summary .signal:text-is("${state}")`).count(), 1, state);
    assert.equal(await page.locator('details.deploy-run[open]').count(), 2, 'the unresolved failure and the run needing attention open');
    assert.equal(await page.locator('details.deploy-run summary:has-text("needs attention")').count(), 1);
    assert.ok((await page.locator('details.deploy-run[open]').last().textContent()).includes('closed without merge <b>x</b>'));
    assert.equal(await page.locator('details.deploy-run b:text-is("x")').count(), 0, 'observation detail is escaped');
    assert.equal(await page.locator('img').count(), 0, 'verification detail is escaped');
    assert.equal(await page.locator('[data-artifact-name="evil"]').count(), 0, 'non-workspace artifact URLs are dropped');
    await page.selectOption('[data-deploy-filter="status"]', 'failed');
    assert.equal(await runs.count(), 1);
    await page.getByRole('button', {name:'apply.log'}).click();
    const viewer = page.locator('dialog[open] pre');
    await page.waitForFunction(() => document.querySelector('dialog[open] pre')?.textContent.includes('safe log <script>'));
    assert.equal(await page.locator('dialog[open] script').count(), 0);
    assert.deepEqual(artifactRequests[0].query, {target:'default', run:'fixture-failed', name:'apply.log', repository:REPOSITORY});
    assert.equal(artifactRequests[0].key, 'k'.repeat(40));
    assert.ok((await viewer.textContent()).includes('safe log <script>'));
    await page.locator('dialog[open] button', {hasText:'Close'}).click();
    await page.selectOption('[data-deploy-filter="status"]', '');
    await page.selectOption('[data-deploy-filter="target"]', 'other');
    assert.equal(await runs.count(), 1);
    assert.equal(await page.locator('details.deploy-run summary .signal').textContent(), 'succeeded');
    assert.deepEqual(errors, []);
    if (process.env.SCREENSHOT) await page.screenshot({path:process.env.SCREENSHOT, fullPage:true});
    console.log('PASS: workspace Deployments view: seven states, observations, filters, scoped artifact viewer and text safety');
  } finally { await browser.close(); }
})().catch(e => { console.error(e); process.exit(1); });
