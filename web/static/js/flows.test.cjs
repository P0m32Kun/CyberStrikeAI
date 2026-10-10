const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const assert = require('node:assert/strict');
const source = fs.readFileSync('web/static/js/flows.js', 'utf8');

// 与仓库其他 *.test.cjs 一致：vm 上下文 + mock document/apiFetch，整文件加载走真实包装层
function escapeHtmlMock(text) {
    return String(text == null ? '' : text).replace(/[&<>"']/g, ch => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[ch]));
}

function makeElement(overrides) {
    return Object.assign({innerHTML: '', textContent: '', value: '', hidden: false, disabled: false, style: {}, dispatchEvent() {}, focus() {}}, overrides);
}

const FILTER_IDS = ['flow-project-filter', 'flow-search', 'flow-host-filter', 'flow-method-filter', 'flow-status-filter', 'flow-tag-filter'];

function flowListPayload() {
    return {
        total: 2,
        items: [
            {id: 'f1', ts: '2026-10-10T08:00:00Z', method: 'GET', url: 'https://a.example.com/api/login?x=1', host: 'a.example.com', status: 200, source: 'agent', tags: ['auth'], project_id: 'p1'},
            {id: 'f2', ts: '2026-10-10T09:00:00Z', method: 'POST', url: 'https://b.example.com/upload<img>', host: 'b.example.com', status: 502, source: 'tool', tags: [], project_id: 'p1'}
        ]
    };
}

function harness(options = {}) {
    const elements = {
        'flow-table-body': makeElement(),
        'flow-pagination': makeElement(),
        'flow-list-meta': makeElement(),
        'flow-detail-body': makeElement(),
        'flow-detail-subtitle': makeElement(),
        'flow-detail-modal': makeElement(),
        'flow-tags-input': makeElement(),
        'flow-detail-save-tags': makeElement(),
        'chat-input': makeElement()
    };
    FILTER_IDS.forEach(id => { elements[id] = makeElement(); });
    const requests = [];
    const calls = [];
    const toasts = [];
    const alerts = [];
    const logs = [];
    const ctx = vm.createContext({
        document: {getElementById: id => elements[id], addEventListener() {}},
        window: {},
        localStorage: {getItem: () => null, setItem() {}},
        URLSearchParams,
        Event: class Event {constructor(type, init) {this.type = type; this.bubbles = !!(init && init.bubbles);}},
        escapeHtml: escapeHtmlMock,
        apiFetch: options.apiFetch || (async (url, req) => {
            requests.push({url, ...req});
            if (url.startsWith('/api/projects')) {
                return {ok: true, json: async () => ({projects: [{id: 'p1', name: '项目一'}, {id: 'p2', name: '项目二'}]})};
            }
            return {ok: true, json: async () => flowListPayload()};
        }),
        switchPage: page => calls.push(['switchPage', page]),
        startNewConversation: opts => {
            calls.push(['startNewConversation', opts]);
            return Promise.resolve();
        },
        openAppModal: id => calls.push(['openAppModal', id]),
        closeAppModal: id => calls.push(['closeAppModal', id]),
        showInlineToast: message => toasts.push(message),
        alert: message => alerts.push(message),
        console: {warn: (...a) => logs.push(['warn', ...a]), error: (...a) => logs.push(['error', ...a])}
    });
    vm.runInContext(source, ctx);
    return {ctx, elements, requests, calls, toasts, alerts, logs};
}

function setFilters(elements, values) {
    Object.entries(values).forEach(([id, value]) => { elements[id].value = value; });
}

test('filter params map to API names and empty values are omitted', () => {
    const h = harness();
    setFilters(h.elements, {
        'flow-search': ' login ',
        'flow-host-filter': 'a.example.com',
        'flow-method-filter': 'POST',
        'flow-status-filter': '401',
        'flow-tag-filter': 'auth',
        'flow-project-filter': 'p1'
    });
    const params = h.ctx.buildFlowsFilterParams();
    assert.equal(params.get('q'), 'login');
    assert.equal(params.get('host'), 'a.example.com');
    assert.equal(params.get('method'), 'POST');
    assert.equal(params.get('status'), '401');
    assert.equal(params.get('tag'), 'auth');
    assert.equal(params.get('project_id'), 'p1');
    assert.equal(params.toString().split('&').length, 6);

    const h2 = harness();
    assert.equal(h2.ctx.buildFlowsFilterParams().toString(), '');
});

test('loadFlows sends limit/offset plus filters, renders and escapes rows', async () => {
    const h = harness();
    setFilters(h.elements, {'flow-search': 'login', 'flow-method-filter': 'GET'});
    await h.ctx.loadFlows(0);
    assert.equal(h.requests.length, 1);
    assert.equal(h.requests[0].url, '/api/http-flows?q=login&method=GET&limit=50&offset=0');
    const rows = h.elements['flow-table-body'].innerHTML;
    assert.match(rows, /GET/);
    assert.match(rows, /https:\/\/a\.example\.com\/api\/login\?x=1/);
    assert.match(rows, /a\.example\.com/);
    assert.match(rows, /agent/);
    assert.match(rows, /auth/);
    assert.match(rows, /openFlowDetail\(0\)/);
    assert.match(rows, /openFlowDetail\(1\)/);
    // 恶意 URL 必须被转义，不能把 <img> 注进行内 HTML
    assert.doesNotMatch(rows, /<img>/);
    assert.match(rows, /&lt;img&gt;/);
    // 状态色走仓内 status-badge 配色族：200=绿、502=红
    assert.match(rows, /class="status-badge status-confirmed"/);
    assert.match(rows, /class="status-badge status-false_positive"/);
    assert.match(h.elements['flow-list-meta'].textContent, /共 2 条/);
});

test('loadFlows without explicit offset syncs project options first', async () => {
    const h = harness();
    await h.ctx.loadFlows();
    assert.equal(h.requests[0].url, '/api/projects?limit=500');
    assert.match(h.requests[1].url, /^\/api\/http-flows\?limit=50&offset=0$/);
    const options = h.elements['flow-project-filter'].innerHTML;
    assert.match(options, /value="p1"/);
    assert.match(options, /value="p2"/);
});

test('loadFlows failure keeps the page usable with an error row', async () => {
    const h = harness({apiFetch: async () => ({ok: false, text: async () => 'boom'})});
    await h.ctx.loadFlows(0);
    assert.match(h.elements['flow-table-body'].innerHTML, /加载流量失败/);
});

test('pagination converts page clicks to offsets and supports page size change', async () => {
    const h = harness({apiFetch: async url => {
        h.requests.push({url});
        return {ok: true, json: async () => ({total: 120, items: flowListPayload().items})};
    }});
    await h.ctx.loadFlows(0);
    assert.equal(h.ctx.flowsTotalPages(), 3);
    assert.match(h.elements['flow-pagination'].innerHTML, /第 1 \/ 3 页/);

    await h.ctx.flowsGoToPage(2);
    assert.equal(h.requests[1].url, '/api/http-flows?limit=50&offset=50');
    assert.match(h.elements['flow-pagination'].innerHTML, /第 2 \/ 3 页/);

    await h.ctx.flowsGoToPage(99); // 越界回夹到最后一页
    assert.equal(h.requests[2].url, '/api/http-flows?limit=50&offset=100');

    h.elements['flow-page-size-pagination'] = makeElement({value: '100'});
    await h.ctx.changeFlowsPageSize();
    assert.equal(h.requests[3].url, '/api/http-flows?limit=100&offset=0');
});

test('openFlowDetail loads the detail endpoint, renders preview and truncation hint', async () => {
    const h = harness({apiFetch: async url => {
        h.requests.push({url});
        if (url === '/api/http-flows/f1') {
            return {ok: true, json: async () => ({
                id: 'f1', ts: '2026-10-10T08:00:00Z', method: 'GET', url: 'https://a.example.com/api/login?x=1',
                host: 'a.example.com', status: 200, source: 'agent', content_type: 'application/json',
                req_len: 128, resp_len: 4096, tags: ['auth'], project_id: 'p1',
                req_headers: {Host: 'a.example.com', Authorization: 'Bearer x'},
                req_body: 'u=1', resp_headers: {'Content-Type': 'application/json'}, resp_body: '{"ok":true}',
                body_truncated: true
            })};
        }
        return {ok: true, json: async () => flowListPayload()};
    }});
    await h.ctx.loadFlows(0);
    await h.ctx.openFlowDetail(0);
    assert.deepEqual(h.calls.filter(call => call[0] === 'openAppModal'), [['openAppModal', 'flow-detail-modal']]);
    assert.equal(h.elements['flow-detail-subtitle'].textContent, 'GET https://a.example.com/api/login?x=1');
    const detail = h.elements['flow-detail-body'].innerHTML;
    assert.match(detail, /Host: a\.example\.com/);
    assert.match(detail, /Bearer x/);
    assert.match(detail, /\{&quot;ok&quot;:true\}/);
    assert.match(detail, /已截断/);
    assert.match(detail, /前 8KB/);
    assert.match(detail, /value="auth"/);
});

test('double-clicking rows keeps only the last clicked detail when the first response is slow', async () => {
    const responders = {};
    const h = harness({apiFetch: url => {
        h.requests.push({url});
        if (url.startsWith('/api/http-flows/')) {
            const id = url.split('/').pop();
            return new Promise(resolve => {
                responders[id] = () => resolve({ok: true, json: async () => ({
                    id, method: 'GET', url: id === 'f1' ? 'https://a.example.com/first' : 'https://b.example.com/second',
                    status: 200, tags: [], req_headers: {}, resp_headers: {}, req_body: '', resp_body: '', body_truncated: false
                })});
            });
        }
        return Promise.resolve({ok: true, json: async () => flowListPayload()});
    }});
    await h.ctx.loadFlows(0);
    const first = h.ctx.openFlowDetail(0);  // 点 A（慢）
    const second = h.ctx.openFlowDetail(1); // 点 B（快）
    responders.f2();
    await second;
    assert.equal(h.elements['flow-detail-subtitle'].textContent, 'GET https://b.example.com/second');
    responders.f1();                          // A 后到：必须被令牌丢弃
    await first;
    assert.equal(h.elements['flow-detail-subtitle'].textContent, 'GET https://b.example.com/second');
    assert.equal(vm.runInContext('flowsState.detail.id', h.ctx), 'f2');
});

test('slow stale list responses never overwrite a newer page render', async () => {
    const responders = [];
    const h = harness({apiFetch: () => new Promise(resolve => { responders.push(resolve); })});
    const pageTwo = [{id: 'p2f1', ts: '2026-10-10T10:00:00Z', method: 'GET', url: 'https://page2.example.com/x', host: 'page2.example.com', status: 200, source: 'agent', tags: [], project_id: 'p1'}];
    const slow = h.ctx.loadFlows(0);   // 旧页（慢）
    const fast = h.ctx.loadFlows(50);  // 新页（后发先至）
    responders[1]({ok: true, json: async () => ({total: 120, items: pageTwo})});
    await fast;
    assert.match(h.elements['flow-table-body'].innerHTML, /page2\.example\.com/);
    assert.match(h.elements['flow-list-meta'].textContent, /共 120 条/);
    responders[0]({ok: true, json: async () => flowListPayload()}); // 旧响应后到：不得覆盖
    await slow;
    assert.match(h.elements['flow-table-body'].innerHTML, /page2\.example\.com/);
    assert.match(h.elements['flow-list-meta'].textContent, /共 120 条/);
});

test('saveFlowTags posts the parsed tag list and updates the row', async () => {
    const h = harness({apiFetch: async (url, req) => {
        h.requests.push({url, ...req});
        if (url === '/api/http-flows/f1') {
            return {ok: true, json: async () => ({...flowListPayload().items[0], req_headers: {}, resp_headers: {}, req_body: '', resp_body: '', body_truncated: false})};
        }
        if (url === '/api/http-flows/f1/tags') {
            return {ok: true, json: async () => ({ok: true})};
        }
        return {ok: true, json: async () => flowListPayload()};
    }});
    await h.ctx.loadFlows(0);
    await h.ctx.openFlowDetail(0);
    h.elements['flow-tags-input'].value = ' web , auth ,login';
    await h.ctx.saveFlowTags();
    const tagRequest = h.requests.find(request => request.url === '/api/http-flows/f1/tags');
    assert.equal(tagRequest.method, 'POST');
    assert.equal(tagRequest.headers['Content-Type'], 'application/json');
    assert.deepEqual(JSON.parse(tagRequest.body), {tags: ['web', 'auth', 'login']});
    assert.match(h.elements['flow-table-body'].innerHTML, /login/);
    assert.equal(h.elements['flow-detail-save-tags'].disabled, false);
    assert.deepEqual(h.toasts, ['标签已保存']);
});

test('sendFlowToAgent prefills a fresh chat after switching page, waiting for the new conversation', async () => {
    let releaseConversation;
    const h = harness({apiFetch: async url => {
        h.requests.push({url});
        if (url === '/api/http-flows/f1') {
            return {ok: true, json: async () => ({
                id: 'f1', method: 'POST', url: 'https://a.example.com/login', status: 401, host: 'a.example.com',
                tags: ['auth'], project_id: 'p1',
                req_headers: {Host: 'a.example.com'}, req_body: 'u=1&p=2',
                resp_headers: {'Content-Type': 'text/html'}, resp_body: '<html>denied</html>', body_truncated: true
            })};
        }
        return {ok: true, json: async () => flowListPayload()};
    }});
    h.ctx.startNewConversation = opts => {
        h.calls.push(['startNewConversation', opts]);
        return new Promise(resolve => {releaseConversation = resolve;});
    };
    await h.ctx.loadFlows(0);
    await h.ctx.openFlowDetail(0);
    const pending = h.ctx.sendFlowToAgent();
    // 新会话完成前不预填（新会话完成时会把输入框清空）
    assert.equal(h.elements['chat-input'].value, '');
    releaseConversation();
    await pending;
    // openAppModal（开详情）→ closeAppModal（发给 Agent 先关弹窗再切页）→ switchPage → startNewConversation
    assert.deepEqual(h.calls.map(call => call[0]), ['openAppModal', 'closeAppModal', 'switchPage', 'startNewConversation']);
    assert.ok(h.calls.findIndex(call => call[0] === 'closeAppModal') < h.calls.findIndex(call => call[0] === 'switchPage'), '详情弹窗必须先于切页关闭');
    assert.deepEqual(h.calls.find(call => call[0] === 'switchPage'), ['switchPage', 'chat']);
    // opts 对象产生自 vm 上下文（跨 realm 原型不同），逐字段断言
    const conversationOptions = h.calls.find(call => call[0] === 'startNewConversation')[1];
    assert.equal(conversationOptions.projectId, 'p1');
    assert.deepEqual(Object.keys(conversationOptions), ['projectId']);
    const summary = h.elements['chat-input'].value;
    assert.match(summary, /POST https:\/\/a\.example\.com\/login \(401\)/);
    assert.match(summary, /u=1&p=2/);
    assert.match(summary, /&lt;html&gt;denied&lt;\/html&gt;|<html>denied<\/html>/);
    assert.match(summary, /已截断/);
    assert.deepEqual(h.toasts, ['流量摘要已填入对话输入框']);
});

test('sendFlowToAgent does nothing without an open detail', async () => {
    const h = harness();
    await h.ctx.sendFlowToAgent();
    assert.equal(h.calls.length, 0);
    assert.equal(h.alerts.length, 0);
});
