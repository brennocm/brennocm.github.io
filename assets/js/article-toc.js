/**
 * Índice lateral dos artigos.
 *
 * Nas páginas-guia o índice é escrito à mão (tem subníveis); nos demais
 * artigos ele é montado aqui a partir dos <h2> do corpo. Nos dois casos, a
 * seção que está sendo lida fica marcada enquanto a página rola.
 *
 * A seção corrente é a última cujo título já passou pela linha de leitura
 * (logo abaixo do header fixo) — o mesmo critério que o leitor usa
 * visualmente, e que não depende do tamanho da seção.
 */
(function () {
    'use strict';

    var LINE = 120;

    function slug(text) {
        return text.toLowerCase()
            .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
            .replace(/[^a-z0-9]+/g, '-')
            .replace(/^-+|-+$/g, '') || 'secao';
    }

    /* Monta o índice quando a página não traz um. */
    function buildToc() {
        var content = document.querySelector('.content');
        var body = document.querySelector('.article-body');
        if (!content || !body) return null;

        var headings = Array.prototype.slice.call(body.querySelectorAll('h2'));
        // com uma seção só não há o que navegar
        if (headings.length < 2) return null;

        var used = {};
        var nav = document.createElement('nav');
        nav.className = 'toc';

        var title = document.createElement('h2');
        title.textContent = document.documentElement.lang === 'en' ? 'Contents' : 'Índice';
        nav.appendChild(title);

        var list = document.createElement('ul');
        headings.forEach(function (heading) {
            if (!heading.id) {
                var base = slug(heading.textContent);
                var id = base;
                var n = 2;
                while (used[id] || document.getElementById(id)) id = base + '-' + n++;
                used[id] = true;
                heading.id = id;
            }
            var item = document.createElement('li');
            var link = document.createElement('a');
            link.href = '#' + heading.id;
            link.textContent = heading.textContent;
            item.appendChild(link);
            list.appendChild(item);
        });
        nav.appendChild(list);

        content.insertBefore(nav, body);
        return nav;
    }

    var toc = document.querySelector('.toc') || buildToc();
    if (!toc) return;

    var entries = Array.prototype.slice.call(toc.querySelectorAll('a[href^="#"]'))
        .map(function (link) {
            return { link: link, heading: document.getElementById(decodeURIComponent(link.hash.slice(1))) };
        })
        .filter(function (entry) {
            return entry.heading;
        });
    if (!entries.length) return;

    var current = null;
    var currentGroup = null;
    var ticking = false;

    function update() {
        ticking = false;

        var active = null;
        for (var i = 0; i < entries.length; i++) {
            if (entries[i].heading.getBoundingClientRect().top <= LINE) active = entries[i];
        }
        // na introdução, antes do primeiro título, nenhuma seção está sendo lida

        // no fim da página a última seção é a corrente, mesmo que curta demais
        // para alcançar a linha de leitura
        var scrollable = document.body.offsetHeight > window.innerHeight + 4;
        if (scrollable && window.innerHeight + window.scrollY >= document.body.offsetHeight - 2) {
            active = entries[entries.length - 1];
        }

        if (active === current) return;

        if (current) current.link.classList.remove('active');
        if (currentGroup) {
            currentGroup.classList.remove('active-group');
            currentGroup = null;
        }
        current = active;
        if (!active) return;

        active.link.classList.add('active');

        // um item de sub-lista também acende o grupo a que pertence
        var sublist = active.link.closest('ul ul');
        currentGroup = sublist ? sublist.parentNode.querySelector('a') : null;
        if (currentGroup) currentGroup.classList.add('active-group');
    }

    function onScroll() {
        if (ticking) return;
        ticking = true;
        requestAnimationFrame(update);
    }

    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('resize', onScroll);
    update();
})();
