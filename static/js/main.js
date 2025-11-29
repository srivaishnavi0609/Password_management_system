document.addEventListener('DOMContentLoaded', () => {
    // On dashboard: load credentials
    const credTbody = document.getElementById('cred-tbody');
    const emptyMsg = document.getElementById('empty-msg');
    if (credTbody) {
        fetch('/api/credentials')
            .then(r => r.json())
            .then(data => {
                if (Array.isArray(data) && data.length > 0) {
                    emptyMsg && (emptyMsg.style.display = 'none');
                    data.forEach(addCredentialRow);
                } else {
                    emptyMsg && (emptyMsg.style.display = 'block');
                }
            })
            .catch(err => {
                console.error('Error loading credentials', err);
            });
    }

    // Add credential form handler
    const addForm = document.getElementById('add-cred-form');
    if (addForm) {
        addForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const formData = new FormData(addForm);
            const payload = {
                site_name: formData.get('site_name'),
                site_url: formData.get('site_url'),
                username: formData.get('username'),
                password: formData.get('password')
            };

            fetch('/api/credentials', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            })
              .then(r => r.json())
              .then(res => {
                  if (res.error) {
                      alert('Error: ' + res.error);
                  } else {
                      window.location.href = '/dashboard';
                  }
              })
              .catch(err => {
                  console.error('Error saving credential', err);
                  alert('Error saving credential');
              });
        });

        // Password generator
        const genBtn = document.getElementById('generate-btn');
        const pwdField = document.getElementById('password-field');
        const lenInput = document.getElementById('gen-length');
        const lowerCb = document.getElementById('gen-lower');
        const upperCb = document.getElementById('gen-upper');
        const digitsCb = document.getElementById('gen-digits');
        const symbolsCb = document.getElementById('gen-symbols');

        if (genBtn) {
            genBtn.addEventListener('click', () => {
                const length = parseInt(lenInput.value, 10) || 16;
                const options = {
                    lower: lowerCb.checked,
                    upper: upperCb.checked,
                    digits: digitsCb.checked,
                    symbols: symbolsCb.checked
                };
                const pwd = generatePassword(length, options);
                pwdField.value = pwd;
            });
        }
    }
});

// Add row to credentials table
function addCredentialRow(cred) {
    const tbody = document.getElementById('cred-tbody');
    if (!tbody) return;

    const tr = document.createElement('tr');
    tr.innerHTML = `
        <td>${escapeHtml(cred.site_name || '')}</td>
        <td>${cred.site_url ? `<a href="${escapeAttr(cred.site_url)}" target="_blank">Link</a>` : ''}</td>
        <td>${escapeHtml(cred.username || '')}</td>
        <td>
            <span class="password-mask">••••••••••</span>
            <span class="password-value" style="display:none;">${escapeHtml(cred.password || '')}</span>
            <button type="button" class="toggle-pwd-btn">Show</button>
        </td>
        <td>
            <button type="button" class="delete-btn" data-id="${cred.id}">Delete</button>
        </td>
    `;
    tbody.appendChild(tr);

    const toggleBtn = tr.querySelector('.toggle-pwd-btn');
    const maskSpan = tr.querySelector('.password-mask');
    const valueSpan = tr.querySelector('.password-value');

    toggleBtn.addEventListener('click', () => {
        if (valueSpan.style.display === 'none') {
            valueSpan.style.display = 'inline';
            maskSpan.style.display = 'none';
            toggleBtn.textContent = 'Hide';
        } else {
            valueSpan.style.display = 'none';
            maskSpan.style.display = 'inline';
            toggleBtn.textContent = 'Show';
        }
    });

    const delBtn = tr.querySelector('.delete-btn');
    delBtn.addEventListener('click', () => {
        const id = delBtn.getAttribute('data-id');
        if (!confirm('Delete this credential?')) return;

        fetch(`/api/credentials/${id}`, { method: 'DELETE' })
          .then(r => r.json())
          .then(res => {
              if (res.status === 'deleted') {
                  tr.remove();
              } else {
                  alert('Error deleting credential');
              }
          })
          .catch(err => {
              console.error('Error deleting credential', err);
              alert('Error deleting credential');
          });
    });
}

// Password generator
function generatePassword(length, opts) {
    let chars = '';
    if (opts.lower) chars += 'abcdefghijklmnopqrstuvwxyz';
    if (opts.upper) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (opts.digits) chars += '0123456789';
    if (opts.symbols) chars += '!@#$%^&*()-_=+[]{};:,.<>/?';

    if (!chars) {
        chars = 'abcdefghijklmnopqrstuvwxyz';
    }

    let result = '';
    const arr = new Uint32Array(length);
    window.crypto.getRandomValues(arr);
    for (let i = 0; i < length; i++) {
        const idx = arr[i] % chars.length;
        result += chars.charAt(idx);
    }
    return result;
}

// Simple escaping helpers
function escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, s => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    }[s]));
}

function escapeAttr(str) {
    return escapeHtml(str).replace(/"/g, '&quot;');
}