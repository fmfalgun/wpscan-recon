(function () {
  function param(name) {
    return new URLSearchParams(window.location.search).get(name);
  }
  function setText(id, val) {
    var el = document.getElementById(id);
    if (el) el.textContent = val != null ? String(val) : '—';
  }

  function addExposureItem(grid, key, val, extraClass) {
    if (!grid) return;
    var item = document.createElement('div');
    item.className = 'exposure-item';
    var vCls = 'exposure-val' + (extraClass ? ' ' + extraClass : '');
    item.innerHTML = '<span class="exposure-key">' + key + '</span><span class="' + vCls + '">' + val + '</span>';
    grid.appendChild(item);
  }

  document.addEventListener('DOMContentLoaded', function () {
    var d = param('d');
    if (!d) { window.location.href = 'wp-board.html'; return; }

    fetch('data/sites/' + d + '.json')
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (data) {
        setText('site-url-display', data.url || d);
        var contribEl = document.getElementById('contributor-meta');
        if (contribEl && data.display_name) {
          contribEl.textContent = data.display_name + (data.display_loc ? ' · ' + data.display_loc : '');
        }

        // Stat badges
        var verEl = document.getElementById('val-wp-version');
        if (verEl) {
          verEl.textContent = data.wp_version || '—';
          var status = data.wp_version_status || 'unknown';
          verEl.style.color = status === 'latest' ? 'var(--green)' : status === 'outdated' ? 'var(--red)' : '';
        }
        setText('val-vuln-count',   data.vuln_count   || 0);
        setText('val-plugin-count', data.plugin_count || 0);
        setText('val-user-count',   data.user_count   || 0);

        var vulnEl = document.getElementById('val-vuln-count');
        if (vulnEl) vulnEl.style.color = (data.vuln_count || 0) > 0 ? 'var(--red)' : 'var(--green)';

        setText('scanned-at', (data.scanned_at || '').slice(0, 10));

        // Exposure summary
        var expGrid = document.getElementById('exposure-grid');
        if (expGrid) {
          expGrid.className = 'exposure-grid';
          addExposureItem(expGrid, 'Method',        data.method    || '—', '');
          addExposureItem(expGrid, 'API Token',     data.api_token_used ? 'YES — vuln data included' : 'NO — vulns may be incomplete', data.api_token_used ? 'safe' : '');
          addExposureItem(expGrid, 'xmlrpc.php',    data.xmlrpc_active  ? 'EXPOSED — brute-force risk' : 'not found', data.xmlrpc_active  ? 'exposed' : 'safe');
          addExposureItem(expGrid, 'readme.html',   data.readme_exposed ? 'EXPOSED — version disclosure' : 'not found', data.readme_exposed ? 'exposed' : 'safe');
        }

        // Interesting findings
        var findList = document.getElementById('findings-list');
        var findings = data.interesting_findings || [];
        if (findList) {
          if (!findings.length) {
            findList.innerHTML = '<span class="empty">No interesting findings.</span>';
          } else {
            findings.forEach(function (f) {
              var item = document.createElement('div');
              item.className = 'finding-item';
              item.innerHTML =
                '<div class="finding-type">' + (f.type || 'unknown') + '</div>' +
                '<div class="finding-url">' + (f.url || '') + '</div>' +
                (f.message ? '<div class="finding-msg">' + f.message + '</div>' : '');
              findList.appendChild(item);
            });
          }
        }

        // Plugins
        var pluginsCont = document.getElementById('plugins-container');
        var plugins = data.plugins || [];
        if (pluginsCont) {
          if (!plugins.length) {
            pluginsCont.innerHTML = '<span class="empty">No plugins detected' + (data.method === 'http_fallback' ? ' (HTTP fallback mode — install wpscan for full enumeration)' : '') + '.</span>';
          } else {
            var tbl = '<table class="plugins-table"><thead class="plugins-thead"><tr>' +
              '<th class="col-slug">Slug</th><th class="col-version">Version</th><th class="col-vulns">Vulns</th>' +
              '</tr></thead><tbody>';
            plugins.forEach(function (p) {
              var vulnCls = (p.vuln_count || 0) > 0 ? 'has-vulns' : 'zero-vulns';
              tbl += '<tr class="plugins-row">' +
                '<td class="col-slug">' + p.slug + '</td>' +
                '<td class="col-version">' + (p.version || '—') + '</td>' +
                '<td class="col-vulns ' + vulnCls + '">' + (p.vuln_count || 0) + '</td>' +
                '</tr>';
            });
            tbl += '</tbody></table>';
            pluginsCont.innerHTML = tbl;
          }
        }

        // Users
        var userList = document.getElementById('users-list');
        var users = data.users || [];
        if (userList) {
          if (!users.length) {
            userList.innerHTML = '<span class="empty">No users enumerated.</span>';
          } else {
            users.forEach(function (u) {
              var item = document.createElement('div');
              item.className = 'user-item';
              item.innerHTML =
                '<span class="user-login">' + u.login + '</span>' +
                '<span class="user-meta">' + (u.display_name || '') + (u.id ? '  [id: ' + u.id + ']' : '') + '</span>';
              userList.appendChild(item);
            });
          }
        }
      })
      .catch(function (err) {
        var box = document.getElementById('error-box');
        var msg = document.getElementById('error-message');
        if (box) box.style.display = 'block';
        if (msg) msg.textContent = 'Failed to load "' + d + '": ' + err.message;
      });
  });
})();
