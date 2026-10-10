// 流量页（Phase 3）：项目维度的 HTTP 流量检索与检视。
// API 合同（与后端约定，勿自行变更）：
//   GET  /api/http-flows?project_id=&q=&host=&method=&status=&tag=&limit=50&offset=0
//   GET  /api/http-flows/{id}          （含 req/resp 头与 ≤8KB 正文预览、body_truncated）
//   POST /api/http-flows/{id}/tags     {"tags":["..."]} → {"ok":true}
const FLOWS_PAGE_SIZE_KEY = 'cyberstrike.flows_page_size';
const FLOWS_PAGE_SIZES = [20, 50, 100, 200];

function getFlowsPageSize() {
    try {
        const value = Number(localStorage.getItem(FLOWS_PAGE_SIZE_KEY));
        return FLOWS_PAGE_SIZES.includes(value) ? value : 50;
    } catch (error) {
        return 50;
    }
}

const flowsState = {
    offset: 0,
    pageSize: getFlowsPageSize(),
    total: 0,
    items: [],
    detail: null,
    tagsBusy: false,
    projects: [],
    projectsLoaded: false
};

function flowT(key, fallback, options) {
    if (window.i18next && typeof window.i18next.t === 'function') {
        const value = window.i18next.t(key, options || {});
        if (value && value !== key) return value;
    }
    return fallback;
}

function flowEscapeAttr(text) {
    return escapeHtml(text).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function flowLocale() {
    if (typeof window !== 'undefined') {
        if (typeof window.__locale === 'string' && window.__locale) return window.__locale;
        if (typeof window.currentLang === 'string' && window.currentLang) return window.currentLang;
    }
    return 'zh-CN';
}

function formatFlowTime(ts) {
    if (!ts) return '-';
    const date = new Date(ts);
    return isNaN(date.getTime()) ? String(ts) : date.toLocaleString(flowLocale());
}

// 复用 status-badge 配色族表达状态码区间：2xx/3xx=绿、4xx=蓝、5xx=红、其余灰
function flowStatusBadgeClass(status) {
    const code = Number(status);
    if (!Number.isFinite(code) || code <= 0) return '';
    if (code >= 500) return 'status-false_positive';
    if (code >= 400) return 'status-open';
    if (code >= 200 && code < 400) return 'status-confirmed';
    return '';
}

/** 把过滤控件值拼成查询参数（不含分页）；空值不发送，与资产页同一约定 */
function buildFlowsFilterParams() {
    const params = new URLSearchParams();
    const map = {
        'flow-project-filter': 'project_id',
        'flow-search': 'q',
        'flow-host-filter': 'host',
        'flow-method-filter': 'method',
        'flow-status-filter': 'status',
        'flow-tag-filter': 'tag'
    };
    Object.entries(map).forEach(([id, key]) => {
        const value = (document.getElementById(id)?.value || '').trim();
        if (value) params.set(key, value);
    });
    return params;
}

function resetFlowsFilters() {
    ['flow-project-filter', 'flow-search', 'flow-host-filter', 'flow-method-filter', 'flow-status-filter', 'flow-tag-filter'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = '';
    });
    loadFlows(0);
}

async function ensureFlowsProjects(force) {
    if (flowsState.projectsLoaded && !force) return;
    try {
        const response = await apiFetch('/api/projects?limit=500');
        if (!response.ok) throw new Error(await response.text());
        const data = await response.json();
        flowsState.projects = data.projects || [];
        flowsState.projectsLoaded = true;
        populateFlowsProjectSelect();
    } catch (error) {
        console.warn('加载流量页项目选项失败:', error);
        flowsState.projectsLoaded = true;
    }
}

function populateFlowsProjectSelect() {
    const select = document.getElementById('flow-project-filter');
    if (!select) return;
    const current = select.value;
    select.innerHTML = `<option value="">${escapeHtml(flowT('flows.allProjects', '全部项目'))}</option>`
        + flowsState.projects.map(project => `<option value="${flowEscapeAttr(project.id)}">${escapeHtml(project.name || project.id)}</option>`).join('');
    select.value = flowsState.projects.some(project => project.id === current) ? current : '';
}

async function initFlowsPage() {
    await ensureFlowsProjects(true);
    await loadFlows(0);
}

// 乱序渲染守卫（参照 chat.js loadConversationRequestSeq 惯例）：
// 快速翻页/过滤时旧响应可能后到，只有最后发起的请求允许写状态与渲染。
let flowsListRequestSeq = 0;

async function loadFlows(offset) {
    // 无显式 offset 表示进入流量页或点击顶部“刷新”，此时同步项目筛选项
    if (offset == null) await ensureFlowsProjects(true);
    flowsState.offset = Math.max(0, Number(offset || 0));
    const requestSeq = ++flowsListRequestSeq;
    const params = buildFlowsFilterParams();
    params.set('limit', flowsState.pageSize);
    params.set('offset', flowsState.offset);
    const body = document.getElementById('flow-table-body');
    if (body) body.innerHTML = `<tr><td colspan="8" class="muted">${escapeHtml(flowT('common.loading', '加载中...'))}</td></tr>`;
    try {
        const response = await apiFetch('/api/http-flows?' + params.toString());
        if (!response.ok) throw new Error(await response.text());
        const data = await response.json();
        if (requestSeq !== flowsListRequestSeq) return; // 已被更新的请求取代，丢弃乱序旧响应
        flowsState.items = data.items || [];
        flowsState.total = data.total || 0;
        // 过滤后剩余条数不足当前页起点时回退到最后一页，避免停在空页
        const totalPages = Math.max(1, Math.ceil(flowsState.total / flowsState.pageSize));
        if (flowsState.offset >= totalPages * flowsState.pageSize && flowsState.total > 0) {
            return loadFlows((totalPages - 1) * flowsState.pageSize);
        }
        renderFlowsRows();
        renderFlowsPagination();
        updateFlowsMeta();
    } catch (error) {
        if (requestSeq !== flowsListRequestSeq) return; // 过期失败不覆盖新请求的渲染
        console.error('加载流量失败:', error);
        flowsState.items = [];
        flowsState.total = 0;
        if (body) body.innerHTML = `<tr><td colspan="8" class="muted">${escapeHtml(flowT('flows.loadFailed', '加载流量失败'))}</td></tr>`;
        renderFlowsPagination();
        updateFlowsMeta();
    }
}

function flowsTotalPages() {
    return Math.max(1, Math.ceil((flowsState.total || 0) / flowsState.pageSize));
}

function flowsCurrentPage() {
    return Math.floor(flowsState.offset / flowsState.pageSize) + 1;
}

function flowsGoToPage(page) {
    const totalPages = flowsTotalPages();
    const target = Math.min(Math.max(1, Number(page) || 1), totalPages);
    return loadFlows((target - 1) * flowsState.pageSize);
}

function changeFlowsPageSize() {
    const select = document.getElementById('flow-page-size-pagination');
    const size = Number(select?.value);
    if (!FLOWS_PAGE_SIZES.includes(size)) return;
    flowsState.pageSize = size;
    try { localStorage.setItem(FLOWS_PAGE_SIZE_KEY, String(size)); } catch (error) { /* ignore */ }
    return loadFlows(0);
}

function updateFlowsMeta() {
    const meta = document.getElementById('flow-list-meta');
    if (meta) meta.textContent = flowT('flows.totalMeta', `共 ${flowsState.total || 0} 条`, { count: flowsState.total || 0 });
}

function renderFlowsRows() {
    const body = document.getElementById('flow-table-body');
    if (!body) return;
    if (!flowsState.items.length) {
        body.innerHTML = `<tr><td colspan="8" class="muted">${escapeHtml(flowT('common.noData', '暂无数据'))}</td></tr>`;
        return;
    }
    body.innerHTML = flowsState.items.map((flow, index) => {
        const tags = Array.isArray(flow.tags) ? flow.tags : [];
        const tagMarkup = tags.length
            ? tags.map(tag => `<span class="asset-tag">${escapeHtml(tag)}</span>`).join(' ')
            : '<span class="muted">-</span>';
        const statusBadgeClass = flowStatusBadgeClass(flow.status);
        return `<tr>
            <td>${escapeHtml(formatFlowTime(flow.ts))}</td>
            <td><code>${escapeHtml(flow.method || '-')}</code></td>
            <td><button class="asset-target-link" title="${flowEscapeAttr(flow.url || '')}" onclick="openFlowDetail(${index})">${escapeHtml(flow.url || '-')}</button></td>
            <td><span class="status-badge ${statusBadgeClass}">${escapeHtml(flow.status == null ? '-' : String(flow.status))}</span></td>
            <td>${escapeHtml(flow.host || '-')}</td>
            <td>${escapeHtml(flow.source || '-')}</td>
            <td>${tagMarkup}</td>
            <td class="col-actions"><button class="btn-link" onclick="openFlowDetail(${index})">${escapeHtml(flowT('common.view', '详情'))}</button></td>
        </tr>`;
    }).join('');
    if (typeof applyRBACToUI === 'function') applyRBACToUI(body);
}

function renderFlowsPagination() {
    const root = document.getElementById('flow-pagination');
    if (!root) return;
    const page = flowsCurrentPage();
    const totalPages = flowsTotalPages();
    const total = flowsState.total || 0;
    const pageSize = flowsState.pageSize;
    const start = total === 0 ? 0 : (page - 1) * pageSize + 1;
    const end = total === 0 ? 0 : Math.min(page * pageSize, total);
    const atFirst = page <= 1 || total === 0;
    const atLast = page >= totalPages || total === 0;
    root.innerHTML = `<div class="pagination">
        <div class="pagination-info">
            <span>${escapeHtml(flowT('skillsPage.paginationShow', `显示 ${start}-${end} / 共 ${total} 条`, { start, end, total }))}</span>
            <label class="pagination-page-size">${escapeHtml(flowT('skillsPage.perPageLabel', '每页显示'))}
                <select id="flow-page-size-pagination" onchange="changeFlowsPageSize()">
                    ${FLOWS_PAGE_SIZES.map(size => `<option value="${size}" ${size === pageSize ? 'selected' : ''}>${size}</option>`).join('')}
                </select>
            </label>
        </div>
        <div class="pagination-controls">
            <button class="btn-secondary" onclick="flowsGoToPage(1)" ${atFirst ? 'disabled' : ''}>${escapeHtml(flowT('skillsPage.firstPage', '首页'))}</button>
            <button class="btn-secondary" onclick="flowsGoToPage(${Math.max(1, page - 1)})" ${atFirst ? 'disabled' : ''}>${escapeHtml(flowT('skillsPage.prevPage', '上一页'))}</button>
            <span class="pagination-page">${escapeHtml(flowT('skillsPage.pageOf', `第 ${page} / ${totalPages} 页`, { current: page, total: totalPages }))}</span>
            <button class="btn-secondary" onclick="flowsGoToPage(${Math.min(totalPages, page + 1)})" ${atLast ? 'disabled' : ''}>${escapeHtml(flowT('skillsPage.nextPage', '下一页'))}</button>
            <button class="btn-secondary" onclick="flowsGoToPage(${totalPages})" ${atLast ? 'disabled' : ''}>${escapeHtml(flowT('skillsPage.lastPage', '尾页'))}</button>
        </div>
    </div>`;
}

function flowHeadersText(headers) {
    if (!headers) return '';
    if (typeof headers === 'string') return headers;
    if (Array.isArray(headers)) return headers.join('\n');
    return Object.entries(headers).map(([key, value]) => `${key}: ${value}`).join('\n');
}

// 双击竞态守卫：快速连点不同行时，慢的旧响应不允许覆盖最后一次点击
// （成员检查防不住“点 A（慢）→点 B（快）→A 后到”，改用请求令牌，参照 chat.js loadConversationRequestSeq）。
let flowsDetailRequestSeq = 0;

async function openFlowDetail(index) {
    const flow = flowsState.items[Number(index)];
    if (!flow || !flow.id) return;
    if (typeof openAppModal === 'function') openAppModal('flow-detail-modal');
    else {
        const modal = document.getElementById('flow-detail-modal');
        if (modal) modal.style.display = 'block';
    }
    const body = document.getElementById('flow-detail-body');
    if (body) body.innerHTML = `<div class="muted">${escapeHtml(flowT('common.loading', '加载中...'))}</div>`;
    const requestSeq = ++flowsDetailRequestSeq;
    try {
        const response = await apiFetch(`/api/http-flows/${encodeURIComponent(flow.id)}`);
        if (!response.ok) throw new Error(await response.text());
        const detail = await response.json();
        if (requestSeq !== flowsDetailRequestSeq) return; // 只认最后一次点击
        flowsState.detail = detail;
        renderFlowDetail(detail);
    } catch (error) {
        if (requestSeq !== flowsDetailRequestSeq) return;
        console.error('加载流量详情失败:', error);
        flowsState.detail = null;
        if (body) body.innerHTML = `<div class="muted">${escapeHtml(flowT('flows.detailLoadFailed', '加载流量详情失败'))}</div>`;
    }
}

function renderFlowDetail(detail) {
    const subtitle = document.getElementById('flow-detail-subtitle');
    if (subtitle) subtitle.textContent = `${detail.method || '-'} ${detail.url || '-'}`;
    const body = document.getElementById('flow-detail-body');
    if (!body) return;
    const truncated = !!detail.body_truncated;
    const truncatedHint = `<p class="form-hint">${escapeHtml(flowT('flows.bodyTruncated', '正文过长，仅显示前 8KB 预览'))}</p>`;
    body.innerHTML = `
        <div class="asset-detail-grid">
            <div class="detail-info-grid">
                <div class="detail-item"><strong>${escapeHtml(flowT('flows.colTime', '时间'))}</strong><span>${escapeHtml(formatFlowTime(detail.ts))}</span></div>
                <div class="detail-item"><strong>${escapeHtml(flowT('flows.colStatus', '状态码'))}</strong><span class="status-badge ${flowStatusBadgeClass(detail.status)}">${escapeHtml(detail.status == null ? '-' : String(detail.status))}</span></div>
                <div class="detail-item"><strong>${escapeHtml(flowT('flows.colHost', 'Host'))}</strong><span>${escapeHtml(detail.host || '-')}</span></div>
                <div class="detail-item"><strong>${escapeHtml(flowT('flows.colSource', '来源'))}</strong><span>${escapeHtml(detail.source || '-')}</span></div>
                <div class="detail-item"><strong>${escapeHtml(flowT('flows.contentType', 'Content-Type'))}</strong><span>${escapeHtml(detail.content_type || '-')}</span></div>
                <div class="detail-item"><strong>${escapeHtml(flowT('flows.size', '大小'))}</strong><span>req ${escapeHtml(String(detail.req_len == null ? '-' : detail.req_len))}B / resp ${escapeHtml(String(detail.resp_len == null ? '-' : detail.resp_len))}B</span></div>
            </div>
            <label class="asset-editor-field">
                <span>${escapeHtml(flowT('flows.tagsLabel', '标签'))}</span>
                <input id="flow-tags-input" type="text" autocomplete="off" placeholder="${flowEscapeAttr(flowT('flows.tagsPlaceholder', '多个标签用逗号分隔'))}" value="${flowEscapeAttr((Array.isArray(detail.tags) ? detail.tags : []).join(', '))}">
            </label>
            <section>
                <h4>${escapeHtml(flowT('flows.reqHeaders', '请求头'))}</h4>
                <pre class="code-block">${escapeHtml(flowHeadersText(detail.req_headers) || '-')}</pre>
            </section>
            <section>
                <h4>${escapeHtml(flowT('flows.reqBody', '请求正文'))}${truncated ? escapeHtml(' · ' + flowT('flows.truncatedBadge', '已截断')) : ''}</h4>
                <pre class="code-block">${escapeHtml(detail.req_body || '-')}</pre>
            </section>
            <section>
                <h4>${escapeHtml(flowT('flows.respHeaders', '响应头'))}</h4>
                <pre class="code-block">${escapeHtml(flowHeadersText(detail.resp_headers) || '-')}</pre>
            </section>
            <section>
                <h4>${escapeHtml(flowT('flows.respBody', '响应正文'))}${truncated ? escapeHtml(' · ' + flowT('flows.truncatedBadge', '已截断')) : ''}</h4>
                <pre class="code-block">${escapeHtml(detail.resp_body || '-')}</pre>
            </section>
            ${truncated ? truncatedHint : ''}
        </div>`;
}

function closeFlowDetail() {
    flowsState.detail = null;
    const modal = document.getElementById('flow-detail-modal');
    if (!modal) return;
    if (typeof closeAppModal === 'function') closeAppModal('flow-detail-modal');
    else modal.style.display = 'none';
}

async function saveFlowTags() {
    const detail = flowsState.detail;
    if (!detail || !detail.id || flowsState.tagsBusy) return;
    const input = document.getElementById('flow-tags-input');
    const tags = String(input ? input.value : '').split(',').map(tag => tag.trim()).filter(Boolean);
    const button = document.getElementById('flow-detail-save-tags');
    flowsState.tagsBusy = true;
    if (button) button.disabled = true;
    try {
        const response = await apiFetch(`/api/http-flows/${encodeURIComponent(detail.id)}/tags`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tags })
        });
        if (!response.ok) throw new Error(await response.text());
        flowsState.detail.tags = tags;
        const row = flowsState.items.find(item => item.id === detail.id);
        if (row) row.tags = tags.slice();
        renderFlowsRows();
        if (typeof showInlineToast === 'function') showInlineToast(flowT('flows.tagsSaved', '标签已保存'));
    } catch (error) {
        console.error('保存流量标签失败:', error);
        alert(flowT('flows.tagsSaveFailed', '保存标签失败') + ': ' + error.message);
    } finally {
        flowsState.tagsBusy = false;
        if (button) button.disabled = false;
    }
}

/** 生成发给 Agent 的流量摘要（method+url+状态+截断正文） */
function buildFlowAgentSummary(detail) {
    const lines = [
        flowT('flows.agentSummaryHeading', '请分析以下 HTTP 流量：'),
        `${detail.method || '-'} ${detail.url || '-'} (${detail.status == null ? '-' : detail.status})`
    ];
    if (detail.host) lines.push(`Host: ${detail.host}`);
    const tags = Array.isArray(detail.tags) ? detail.tags.filter(Boolean) : [];
    if (tags.length) lines.push(`${flowT('flows.tagsLabel', '标签')}: ${tags.join(', ')}`);
    const reqHeaders = flowHeadersText(detail.req_headers);
    if (reqHeaders) lines.push('', `--- ${flowT('flows.reqHeaders', '请求头')} ---`, reqHeaders);
    if (detail.req_body) lines.push('', `--- ${flowT('flows.reqBody', '请求正文')}${detail.body_truncated ? ` (${flowT('flows.truncatedBadge', '已截断')})` : ''} ---`, detail.req_body);
    const respHeaders = flowHeadersText(detail.resp_headers);
    if (respHeaders) lines.push('', `--- ${flowT('flows.respHeaders', '响应头')} ---`, respHeaders);
    if (detail.resp_body) lines.push('', `--- ${flowT('flows.respBody', '响应正文')}${detail.body_truncated ? ` (${flowT('flows.truncatedBadge', '已截断')})` : ''} ---`, detail.resp_body);
    return lines.join('\n');
}

/**
 * 发给 Agent：复用 info-collect 的“新对话 + 预填输入框”机制——
 * 切到对话页 → 新建会话（继承流量所属项目）→ 摘要填入输入框，由用户确认后发送。
 */
async function sendFlowToAgent() {
    const detail = flowsState.detail;
    if (!detail) return;
    const summary = buildFlowAgentSummary(detail);
    // 详情弹窗是页面区块的兄弟节点，switchPage 不会顺带关掉它；
    // 不先关的话弹窗和 body 滚动锁会悬浮在对话页上，挡住预填的输入框。
    closeFlowDetail();
    if (typeof switchPage === 'function') switchPage('chat');
    else window.location.hash = 'chat';
    try {
        if (typeof startNewConversation === 'function') {
            const maybePromise = startNewConversation({ projectId: detail.project_id || '' });
            if (maybePromise && typeof maybePromise.then === 'function') await maybePromise;
        }
    } catch (error) {
        console.warn('新建会话失败，仍将摘要填入当前输入框:', error);
    }
    const input = document.getElementById('chat-input');
    if (input) {
        input.value = summary;
        input.dispatchEvent(new Event('input', { bubbles: true }));
        input.focus();
    }
    if (typeof showInlineToast === 'function') showInlineToast(flowT('flows.filledToInput', '流量摘要已填入对话输入框'));
}

document.addEventListener('languagechange', () => {
    if (!flowsState.items.length) return;
    renderFlowsRows();
    renderFlowsPagination();
});

window.loadFlows = loadFlows;
window.flowsGoToPage = flowsGoToPage;
window.changeFlowsPageSize = changeFlowsPageSize;
window.resetFlowsFilters = resetFlowsFilters;
window.initFlowsPage = initFlowsPage;
window.openFlowDetail = openFlowDetail;
window.closeFlowDetail = closeFlowDetail;
window.saveFlowTags = saveFlowTags;
window.sendFlowToAgent = sendFlowToAgent;
