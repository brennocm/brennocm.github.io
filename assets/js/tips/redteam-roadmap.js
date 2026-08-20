/**
 * Red Team Roadmap — lógica da guia interativa.
 *
 * Os dados de cada camada vêm de redteam-roadmap.<lang>.js (window.RT_LAYERS),
 * carregado antes deste arquivo. Aqui só ficam a renderização, o filtro, a
 * busca e o progresso. Os textos de interface saem de STRINGS conforme o
 * atributo lang da página — o mesmo critério do article-toc.js.
 *
 * O progresso fica no localStorage sob 'rt_done' e os ids dos tópicos são os
 * mesmos nas duas versões, então marcar um tópico em pt-BR o mantém marcado
 * em en-US e vice-versa.
 */
(function () {
    'use strict';

    var isEN = document.documentElement.lang === 'en';

    var STRINGS = isEN ? {
        topics: 'Topics',
        done: 'Completed',
        filterAll: 'All',
        expand: 'Expand',
        collapse: 'Collapse',
        reset: 'Reset',
        depends: 'Depends on:',
        confirmReset: 'Reset all progress?',
        toastReset: 'Progress reset'
    } : {
        topics: 'Tópicos',
        done: 'Concluídos',
        filterAll: 'Todos',
        expand: 'Expandir',
        collapse: 'Recolher',
        reset: 'Zerar',
        depends: 'Depende de:',
        confirmReset: 'Zerar todo o progresso?',
        toastReset: 'Progresso zerado'
    };

    var L = window.RT_LAYERS || [];

    var DIFF_CLASS = { f: 'd-entry', i: 'd-mid', a: 'd-senior', e: 'd-expert' };
    var DIFF_LABEL = { f: 'entry', i: 'mid', a: 'senior', e: 'expert' };

    var done = new Set();
    var searchStr = '';
    var curFilter = 'all';
    var toastTimer;

    var $ = function (id) { return document.getElementById(id); };

    /* ---------- textos fixos de interface ---------- */
    function applyStrings() {
        $('rt-s-total-label').textContent = STRINGS.topics;
        $('rt-s-done-label').textContent = STRINGS.done;
        $('rt-f-all').textContent = STRINGS.filterAll;
        $('rt-expand').textContent = STRINGS.expand;
        $('rt-collapse').textContent = STRINGS.collapse;
        $('rt-reset').textContent = STRINGS.reset;
    }

    /* ---------- renderização ---------- */
    function render() {
        var c = $('rt-container');
        c.innerHTML = '';
        var totalItems = 0;

        L.forEach(function (layer) {
            var allItems = layer.sections.reduce(function (acc, s) { return acc.concat(s.items); }, []);
            totalItems += allItems.length;
            var doneCount = allItems.filter(function (i) { return done.has(i.id); }).length;

            var card = document.createElement('div');
            card.className = 'layer';
            card.id = 'L' + layer.n;

            var rail = document.createElement('div');
            rail.className = 'rail';
            rail.innerHTML = '<span class="rail-fill"></span>';
            card.appendChild(rail);

            var hdr = document.createElement('div');
            hdr.className = 'layer-hdr';
            hdr.onclick = function () { toggleLayer(card); };
            hdr.innerHTML = '<span class="lnum">' + pad(layer.n) + '</span>' +
                '<div class="linfo">' +
                '<div class="ltitle">' + esc(layer.title) + '</div>' +
                '<div class="ldesc">' + esc(layer.desc) + '</div>' +
                '</div>' +
                '<span class="lprog">' + doneCount + '/' + allItems.length + '</span>' +
                '<span class="ltoggle">›</span>';
            card.appendChild(hdr);

            var body = document.createElement('div');
            body.className = 'lbody';

            layer.sections.forEach(function (sec) {
                var sh = document.createElement('div');
                sh.className = 'section-hdr';
                sh.textContent = sec.t;
                body.appendChild(sh);

                var grid = document.createElement('div');
                grid.className = 'topic-grid';
                sec.items.forEach(function (item) {
                    var ti = document.createElement('div');
                    ti.className = 'ti';
                    ti.dataset.id = item.id;
                    ti.dataset.diff = item.d;
                    var isDone = done.has(item.id);
                    ti.innerHTML = '<span class="chk' + (isDone ? ' done' : '') + '"></span>' +
                        '<span class="titext' + (isDone ? ' done' : '') + '">' + esc(item.t) + '</span>' +
                        '<span class="diff ' + DIFF_CLASS[item.d] + '">' + DIFF_LABEL[item.d] + '</span>';
                    ti.onclick = function () { toggleItem(item.id, ti); };
                    grid.appendChild(ti);
                });
                body.appendChild(grid);
            });

            if (layer.deps.length) {
                var dr = document.createElement('div');
                dr.className = 'dep-row';
                dr.innerHTML = '<span class="dep-label">' + STRINGS.depends + '</span>' +
                    layer.deps.map(function (d) {
                        var t = L.find(function (x) { return x.n === d; });
                        return '<button class="dep-tag" onclick="event.stopPropagation();rtScrollToLayer(' + d + ')">' +
                            pad(d) + ' · ' + esc(t ? t.title : '') + '</button>';
                    }).join('');
                body.appendChild(dr);
            }

            card.appendChild(body);
            c.appendChild(card);
            paintLayer(card);
        });

        $('rt-s-total').textContent = totalItems;
        updateStats();
        applyFilter();
    }

    function paintLayer(card) {
        var items = card.querySelectorAll('.ti');
        var doneC = Array.prototype.filter.call(items, function (t) { return done.has(t.dataset.id); }).length;
        var pct = items.length ? Math.round(doneC / items.length * 100) : 0;
        card.querySelector('.lprog').textContent = doneC + '/' + items.length;
        card.querySelector('.rail-fill').style.height = pct + '%';
        card.classList.toggle('complete', pct === 100);
    }

    function toggleLayer(card) {
        card.querySelector('.lbody').classList.toggle('open');
        card.querySelector('.ltoggle').classList.toggle('open');
    }

    function toggleItem(id, ti) {
        if (done.has(id)) { done.delete(id); } else { done.add(id); }
        var isDone = done.has(id);
        ti.querySelector('.chk').classList.toggle('done', isDone);
        ti.querySelector('.titext').classList.toggle('done', isDone);
        saveProg();
        updateStats();
        paintLayer(ti.closest('.layer'));
    }

    function updateStats() {
        var total = parseInt($('rt-s-total').textContent, 10) || 0;
        $('rt-s-done').textContent = done.size;
        var pct = total ? Math.round(done.size / total * 100) : 0;
        $('rt-prog-fill').style.width = pct + '%';
        $('rt-prog-num').textContent = pct + '%';
    }

    /* exposta no onclick dos botões de filtro */
    window.rtSetFilter = function (btn, f) {
        var btns = document.querySelectorAll('.rt-fbtn');
        Array.prototype.forEach.call(btns, function (b) { b.classList.remove('on'); });
        btn.classList.add('on');
        curFilter = f;
        applyFilter();
    };

    function applyFilter() {
        var q = searchStr.toLowerCase().trim();
        var byDiff = curFilter !== 'all';

        document.querySelectorAll('.layer').forEach(function (card) {
            var vis = true;

            if (vis && q) {
                var titleMatch = card.querySelector('.ltitle').textContent.toLowerCase().indexOf(q) !== -1;
                var hit = Array.prototype.some.call(card.querySelectorAll('.titext'), function (el) {
                    return el.textContent.toLowerCase().indexOf(q) !== -1;
                });
                vis = titleMatch || hit;
                card.querySelectorAll('.ti').forEach(function (ti) {
                    var m = ti.querySelector('.titext').textContent.toLowerCase().indexOf(q) !== -1;
                    ti.classList.toggle('hi', m);
                });
                if (vis && !card.querySelector('.lbody').classList.contains('open')) toggleLayer(card);
            } else {
                card.querySelectorAll('.ti').forEach(function (ti) { ti.classList.remove('hi'); });
            }

            var items = card.querySelectorAll('.ti');
            if (vis && byDiff) {
                if (!Array.prototype.some.call(items, function (ti) { return ti.dataset.diff === curFilter; })) vis = false;
                items.forEach(function (ti) { ti.style.display = ti.dataset.diff === curFilter ? '' : 'none'; });
            } else {
                items.forEach(function (ti) { ti.style.display = ''; });
            }

            card.classList.toggle('hidden', !vis);
        });
    }

    window.rtExpandAll = function () {
        document.querySelectorAll('.layer:not(.hidden) .lbody:not(.open)').forEach(function (b) {
            b.classList.add('open');
            b.parentElement.querySelector('.ltoggle').classList.add('open');
        });
    };

    window.rtCollapseAll = function () {
        document.querySelectorAll('.lbody.open').forEach(function (b) {
            b.classList.remove('open');
            b.parentElement.querySelector('.ltoggle').classList.remove('open');
        });
    };

    window.rtScrollToLayer = function (n) {
        var el = $('L' + n);
        if (!el) return;
        if (!el.querySelector('.lbody').classList.contains('open')) toggleLayer(el);
        el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    };

    window.rtClearProg = function () {
        if (!confirm(STRINGS.confirmReset)) return;
        done.clear();
        try { localStorage.removeItem('rt_done'); } catch (e) { }
        document.querySelectorAll('.chk').forEach(function (c) { c.classList.remove('done'); });
        document.querySelectorAll('.titext').forEach(function (t) { t.classList.remove('done'); });
        document.querySelectorAll('.layer').forEach(paintLayer);
        updateStats();
        toast(STRINGS.toastReset);
    };

    function saveProg() {
        try { localStorage.setItem('rt_done', JSON.stringify([].slice.call(done))); } catch (e) { }
    }

    function loadProg() {
        try {
            var s = localStorage.getItem('rt_done');
            if (s) JSON.parse(s).forEach(function (id) { done.add(id); });
        } catch (e) { }
    }

    function toast(msg) {
        var t = $('rt-toast');
        t.textContent = msg;
        t.classList.add('show');
        clearTimeout(toastTimer);
        toastTimer = setTimeout(function () { t.classList.remove('show'); }, 2500);
    }

    function pad(n) { return String(n).padStart(2, '0'); }

    function esc(s) {
        return String(s).replace(/[&<>"]/g, function (ch) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[ch];
        });
    }

    /* ---------- init ---------- */
    $('rt-search-input').addEventListener('input', function () {
        searchStr = this.value;
        applyFilter();
    });

    applyStrings();
    loadProg();
    render();
})();
