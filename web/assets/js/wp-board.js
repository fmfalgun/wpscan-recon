(function () {
  var DATA_URL = 'data/index.json';

  function wpVerBadge(ver, status) {
    if (!ver) return '<span class="wp-ver-badge wp-ver-unknown">WP —</span>';
    var cls = status === 'latest' ? 'wp-ver-latest' : status === 'outdated' ? 'wp-ver-outdated' : 'wp-ver-unknown';
    return '<span class="wp-ver-badge ' + cls + '">WP ' + ver + '</span>';
  }

  function secBadge(label, exposed) {
    return '<span class="sec-badge ' + (exposed ? 'sec-exposed' : 'sec-safe') + '">' +
      label + (exposed ? ' ✓' : ' ✗') + '</span>';
  }

  function methodBadge(method) {
    var cls  = method === 'wpscan' ? 'method-wpscan' : 'method-fallback';
    var text = method === 'wpscan' ? 'wpscan' : 'http';
    return '<span class="method-badge ' + cls + '">' + text + '</span>';
  }

  function renderCard(entry) {
    var card = document.createElement('div');
    card.className = 'site-card';
    card.setAttribute('data-d', entry.d);

    var vulnCls  = (entry.vuln_count || 0) > 0 ? 'vuln-count-high' : 'vuln-count-zero';
    var vulnText = '<span class="' + vulnCls + '">' + (entry.vuln_count || 0) + ' vulns</span>';

    card.innerHTML =
      '<div class="card-header-row">' +
        '<span class="card-url">' + (entry.url || entry.d) + '</span>' +
        '<span class="card-date">' + (entry.last_refreshed || entry.scanned_at || '').slice(0, 10) + '</span>' +
      '</div>' +
      '<div class="card-stats">' +
        wpVerBadge(entry.wp_version, entry.wp_version_status) + '  ' +
        '<span class="card-stat">' + (entry.plugin_count || 0) + ' plugins</span>' +
        '<span class="card-stat">' + (entry.user_count || 0) + ' users</span>' +
        vulnText + '  ' +
        secBadge('xmlrpc', !!entry.xmlrpc_active) + '  ' +
        secBadge('readme', !!entry.readme_exposed) + '  ' +
        methodBadge(entry.method || 'wpscan') +
      '</div>' +
      '<div class="card-contributor">' +
        '<span class="card-name">' + (entry.display_name || '') + '</span>' +
        '<span>' + (entry.display_loc || '') + '</span>' +
      '</div>';

    card.addEventListener('click', function () {
      window.location.href = 'site.html?d=' + encodeURIComponent(entry.d);
    });
    return card;
  }

  function render(sites) {
    var list = document.getElementById('site-list');
    if (!list) return;
    list.innerHTML = '';
    if (!sites.length) { list.innerHTML = '<p class="empty">No results.</p>'; return; }
    sites.forEach(function (e) { list.appendChild(renderCard(e)); });
  }

  function applySearch(all) {
    var input = document.getElementById('search-input');
    if (!input) return;
    input.addEventListener('input', function () {
      var q = input.value.trim().toLowerCase();
      render(!q ? all : all.filter(function (e) {
        return (e.url || '').toLowerCase().includes(q) || (e.d || '').toLowerCase().includes(q);
      }));
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    fetch(DATA_URL)
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (data) {
        var sites = (data.sites || []).slice().sort(function (a, b) {
          return (b.vuln_count || 0) - (a.vuln_count || 0);
        });

        var statsEl = document.getElementById('wp-stats');
        if (statsEl) {
          var totalVulns  = sites.reduce(function (s, e) { return s + (e.vuln_count || 0); }, 0);
          var xmlrpcCount = sites.filter(function (e) { return e.xmlrpc_active; }).length;
          statsEl.textContent = sites.length + ' site' + (sites.length !== 1 ? 's' : '') +
            ' · ' + totalVulns + ' total vulns · ' + xmlrpcCount + ' xmlrpc exposed';
        }

        render(sites);
        applySearch(sites);
      })
      .catch(function (err) {
        var list = document.getElementById('site-list');
        if (list) list.innerHTML = '<p class="empty">Failed to load: ' + err.message + '</p>';
      });
  });
})();
