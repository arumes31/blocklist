// Delegated replacements for inline on* attributes, so the CSP can forbid
// inline event handlers (script-src-attr 'none'). Markup names a page function
// with data-on-<event>; data-arg0/data-arg1 supply string arguments, where
// "@this" passes the element and "@value" its current value.
(function () {
  'use strict';
  var allowed = new Set([
    'addExcluded', 'addExternalSource', 'addWhitelist', 'applyServerSearch', 'cancelEditTokenPerms',
    'clearSelection', 'closeModal', 'confirmBlock', 'confirmBulkUnblock', 'copySecret',
    'debouncedFilterTable', 'deleteExternalSource', 'editTokenPerms', 'exportData', 'filterCountryList',
    'filterTable', 'loadView', 'navigate', 'openModal', 'refreshExternalSources', 'removeExcluded',
    'removeWhitelist', 'saveCurrentView', 'saveTokenPerms', 'setDensity', 'setReason', 'setTokenTemplate',
    'toggleColumn', 'toggleCountryDropdown', 'toggleExpiryInput', 'toggleSelectAll', 'toggleViewOptions'
  ]);
  var builtins = {
    navigate: function (path) {
      if (typeof path === 'string' && path.charAt(0) === '/' && path.charAt(1) !== '/') window.location.href = path;
    }
  };

  function argument(el, value) {
    if (value === '@this') return el;
    if (value === '@value') return el.value;
    if (value === 'true') return true;
    if (value === 'false') return false;
    return value;
  }

  function dispatch(event) {
    var attr = 'data-on-' + event.type;
    var el = event.target && event.target.closest ? event.target.closest('[' + attr + ']') : null;
    if (!el) return;
    var name = el.getAttribute(attr);
    if (!allowed.has(name)) return;
    var fn = builtins[name] || window[name];
    if (typeof fn !== 'function') return;
    var args = [];
    if (el.hasAttribute('data-arg0')) args.push(argument(el, el.getAttribute('data-arg0')));
    if (el.hasAttribute('data-arg1')) args.push(argument(el, el.getAttribute('data-arg1')));
    fn.apply(el, args);
  }

  ['click', 'change', 'input', 'keyup'].forEach(function (type) {
    document.addEventListener(type, dispatch);
  });
})();
