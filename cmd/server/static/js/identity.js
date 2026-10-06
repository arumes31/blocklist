(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const status = $('identityStatus');
  function report(message, error = false) {
    if (error && $('passwordDialog')?.open) $('passwordDialog').close();
    status.replaceChildren(document.createTextNode(message));
    status.classList.toggle('is-error', error);
    if (error) status.scrollIntoView({block: 'nearest'});
  }
  async function request(path, method, data) {
    const response = await fetch(path, {method, headers: {'Content-Type': 'application/json', Accept: 'application/json'}, body: data === undefined ? undefined : JSON.stringify(data)});
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      if (result.reauth_url) {
        report('Please verify your identity before making this change. ', true);
        const link = document.createElement('a'); link.href = '/sudo?next=' + encodeURIComponent(location.pathname); link.textContent = 'Verify identity'; status.append(link);
        throw new Error('reauth');
      }
      throw new Error(result.error || 'The request could not be completed. Refresh and try again.');
    }
    return result;
  }
  async function save(button, action) {
    const label = button.textContent; button.disabled = true; button.textContent = 'Saving…';
    try { await action(); location.reload(); }
    catch (error) { if (error.message !== 'reauth') report(error.message, true); }
    finally { button.disabled = false; button.textContent = label; }
  }
  if ($('roleForm')) {
    const writable = document.body.dataset.canManage === 'true';
    let selected = null;
    const choices = [...document.querySelectorAll('[name="permission"]')];
    const count = () => { $('permissionCount').textContent = choices.filter(box => box.checked).length + ' of ' + choices.length + ' selected'; };
    function edit(option) {
      selected = option;
      document.querySelectorAll('.role-option').forEach(item => item.setAttribute('aria-pressed', String(item === option)));
      const data = option ? option.dataset : {};
      $('roleEditorTitle').textContent = option ? data.name : 'Create role';
      $('roleKind').textContent = data.builtin === 'true' ? 'Built-in · cannot be deleted' : 'Custom role';
      $('roleName').value = data.name || ''; $('roleKey').value = data.roleId || '';
      $('roleKey').readOnly = !!option; $('roleDescription').value = data.description || '';
      $('roleRevision').value = data.revision || '0'; $('roleExisting').value = data.roleId || '';
      const permissions = (data.permissions || '').split(','); choices.forEach(box => { box.checked = permissions.includes(box.value); });
      if (writable) {
        $('deleteRole').hidden = !option || data.builtin === 'true';
        $('deleteRole').disabled = Number(data.members || 0) > 0;
        $('deleteRole').title = Number(data.members || 0) ? 'Reassign this role’s accounts before deletion' : '';
        $('saveRole').textContent = option ? 'Save changes' : 'Create role';
      }
      count();
    }
    document.querySelectorAll('.role-option').forEach(option => option.addEventListener('click', () => edit(option)));
    choices.forEach(box => box.addEventListener('change', count));
    $('newRole')?.addEventListener('click', () => { edit(null); $('roleName').focus(); });
    $('resetRole')?.addEventListener('click', () => edit(selected));
    $('roleForm').addEventListener('submit', event => {
      event.preventDefault(); if (!writable) return;
      const existing = $('roleExisting').value;
      save($('saveRole'), () => request('/api/v1/roles' + (existing ? '/' + encodeURIComponent(existing) : ''), existing ? 'PUT' : 'POST', {
        id: $('roleKey').value, name: $('roleName').value, description: $('roleDescription').value,
        revision: Number($('roleRevision').value), permissions: choices.filter(box => box.checked).map(box => box.value).join(',')
      }));
    });
    $('deleteRole')?.addEventListener('click', event => {
      if (confirm('Delete the role “' + $('roleName').value + '”? This cannot be undone.')) save(event.currentTarget, () => request('/api/v1/roles/' + encodeURIComponent($('roleExisting').value), 'DELETE'));
    });
    edit(document.querySelector('.role-option'));
  }
  const accountForm = $('accountForm');
  if (accountForm) {
    function syncAccountFields() {
      const entra = $('newAuthSource').value === 'entra';
      $('localPasswordField').hidden = entra; $('newPassword').required = !entra; $('newPassword').disabled = entra;
      $('localUsernameField').hidden = entra; $('newUsername').required = !entra; $('newUsername').disabled = entra;
      $('entraAccountFields').hidden = !entra; $('newEntraUPN').required = entra; $('newEntraUPN').disabled = !entra;
      $('entraRoleHelp').hidden = !entra;
    }
    $('newAuthSource').addEventListener('change', syncAccountFields);
    syncAccountFields();
    accountForm.addEventListener('submit', event => { event.preventDefault(); save(accountForm.querySelector('[type="submit"]'), () => request('/admin_management/create', 'POST', Object.fromEntries(new FormData(accountForm)))); });
  }
  document.querySelectorAll('.account-role-form').forEach(form => form.addEventListener('submit', event => {
    event.preventDefault(); save(form.querySelector('button'), () => request('/admin_management/change_role', 'POST', {username: form.dataset.username, role: form.elements.role.value, entra_role_override: !!form.elements.entra_role_override?.checked}));
  }));
  let passwordUser = '';
  document.querySelectorAll('[data-account-action]').forEach(button => button.addEventListener('click', () => {
    const username = button.dataset.username;
    if (button.dataset.accountAction === 'password') { passwordUser = username; $('passwordAccount').textContent = username; $('replacementPassword').value = ''; $('passwordDialog').showModal(); return; }
    const reset = button.dataset.accountAction === 'mfa';
    if (confirm(reset ? 'Reset authenticator enrollment for “' + username + '”? Existing sessions will be invalidated.' : 'Delete “' + username + '” and their API tokens? This cannot be undone.')) save(button, () => request('/admin_management/' + (reset ? 'change_totp' : 'delete'), 'POST', {username}));
  }));
  $('cancelPassword')?.addEventListener('click', () => $('passwordDialog').close());
  $('passwordForm')?.addEventListener('submit', event => {
    event.preventDefault(); save(event.submitter, async () => { await request('/admin_management/change_password', 'POST', {username: passwordUser, new_password: $('replacementPassword').value}); $('passwordDialog').close(); });
  });
})();
