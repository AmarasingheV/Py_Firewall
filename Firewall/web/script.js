async function fetchData(url) {
       try {
           const response = await fetch(url);
           if (!response.ok) throw new Error(`HTTP error ${response.status}`);
           return await response.json();
       } catch (error) {
           console.error(`Error fetching ${url}:`, error);
           return [];
       }
   }

   function formatBytes(bytes) {
       if (bytes === 0) return '0 Bytes';
       const k = 1024;
       const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
       const i = Math.floor(Math.log(bytes) / Math.log(k));
       return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
   }

   function formatNumber(num) {
       return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
   }

   function toggleNotifications() {
       const box = document.getElementById('notification-box');
       box.style.display = box.style.display === 'none' ? 'block' : 'none';
   }

   async function updateNotifications() {
       const data = await fetchData('/notifications');
       const list = document.getElementById('notifications-list');
       const count = document.getElementById('notification-count');
       list.innerHTML = '';
       data.forEach(item => {
           const li = document.createElement('li');
           li.textContent = `${item.time} - ${item.message}`;
           list.appendChild(li);
       });
       count.textContent = data.length;
       console.log(`Updated notifications: ${data.length} items`);
   }

   async function clearNotifications() {
       await fetch('/clear_notifications', { method: 'POST' });
       await updateNotifications();
   }

   function openTab(evt, tabName) {
       document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
       document.querySelectorAll('.tablinks').forEach(btn => btn.classList.remove('active'));
       document.getElementById(tabName).classList.add('active');
       evt.currentTarget.classList.add('active');
       switch (tabName) {
           case 'NAT':
               updateNATRules();
               toggleNATFields();
               break;
           case 'Clients':
               updateClients();
               break;
           case 'Blacklist':
               updateBlacklist();
               break;
           case 'NetworkScan':
               updateScanResults();
               break;
           case 'Aliases':
               updateAliases();
               break;
           case 'Users':
               updateUsers();
               break;
           case 'Rules':
               updateRules();
               break;
           case 'Logs':
               updateLogs();
               break;
           case 'Status':
               updateInterfaces();
               updateSystemStats();
               updateLogs();
               break;
       }
   }

   async function updateInterfaces() {
       const data = await fetchData('/interfaces');
       const tbody = document.getElementById('interface-body');
       tbody.innerHTML = '';
       Object.entries(data).forEach(([iface, stats]) => {
           const row = document.createElement('tr');
           row.innerHTML = `
               <td>${iface}</td>
               <td>${stats.ip}</td>
               <td>${formatBytes(stats.sent)}</td>
               <td>${formatBytes(stats.recv)}</td>
               <td>${formatNumber(stats.packets_sent)}</td>
               <td>${formatNumber(stats.packets_recv)}</td>
           `;
           tbody.appendChild(row);
       });
       console.log('Updated interfaces');
   }

   async function updateSystemStats() {
       const data = await fetchData('/system_stats');
       document.getElementById('cpu-usage').textContent = `${data.cpu}%`;
       document.getElementById('memory-usage').textContent = `${data.memory}%`;
       console.log('Updated system stats');
   }

   async function updateLogs() {
       console.log('Fetching logs...');
       try {
           const data = await fetchData('/logs');
           // Update Logs tab (<pre id="logs">)
           const logContainer = document.getElementById('logs');
           if (logContainer) {
               if (data.length === 0) {
                   logContainer.textContent = 'No logs available';
                   console.warn('No logs returned for Logs tab');
               } else {
                   logContainer.textContent = data.map(log => `${log.time} - ${log.entry}`).join('\n');
                   console.log(`Updated Logs tab with ${data.length} entries`);
               }
           } else {
               console.error('logs element not found');
           }
           // Update Status tab Recent Logs (<table id="recent_logs">)
           const tbody = document.getElementById('recent_logs')?.querySelector('tbody');
           if (tbody) {
               tbody.innerHTML = '';
               if (data.length === 0) {
                   tbody.innerHTML = '<tr><td colspan="2">No logs available</td></tr>';
                   console.warn('No logs returned for Recent Logs');
               } else {
                   data.slice(-5).forEach(log => {
                       const row = document.createElement('tr');
                       row.innerHTML = `
                           <td>${log.time}</td>
                           <td>${log.entry}</td>
                       `;
                       tbody.appendChild(row);
                   });
                   console.log(`Updated recent_logs with ${data.length} entries`);
               }
           } else {
               console.error('recent_logs tbody not found');
           }
       } catch (error) {
           console.error('Error fetching logs:', error);
           const logContainer = document.getElementById('logs');
           if (logContainer) {
               logContainer.textContent = 'Error loading logs';
           }
           const tbody = document.getElementById('recent_logs')?.querySelector('tbody');
           if (tbody) {
               tbody.innerHTML = '<tr><td colspan="2">Error loading logs</td></tr>';
           }
       }
   }

   async function exportLogs() {
       window.location.href = '/export_logs';
   }

   async function updateRules() {
       const data = await fetchData('/rules');
       const tbody = document.getElementById('rules-body');
       tbody.innerHTML = '';
       data.forEach((rule, index) => {
           const row = document.createElement('tr');
           row.draggable = true;
           row.dataset.index = index;
           row.innerHTML = `
               <td>${index + 1}</td>
               <td>${rule.src_ip || 'Any'}</td>
               <td>${rule.dst_ip || 'Any'}</td>
               <td>${rule.proto || 'Any'}</td>
               <td>${rule.src_port || 'Any'}</td>
               <td>${rule.dst_port || 'Any'}</td>
               <td>${rule.action}</td>
               <td>
                   <button onclick="moveRule(${index}, 'up')">↑</button>
                   <button onclick="moveRule(${index}, 'down')">↓</button>
                   <button onclick="editRule(${index})">Edit</button>
                   <button onclick="deleteRule(${index})">Delete</button>
               </td>
           `;
           row.addEventListener('dragstart', e => e.dataTransfer.setData('text/plain', index));
           row.addEventListener('dragover', e => e.preventDefault());
           row.addEventListener('drop', async e => {
               e.preventDefault();
               const fromIndex = parseInt(e.dataTransfer.getData('text/plain'));
               const toIndex = parseInt(e.target.closest('tr').dataset.index);
               const order = Array.from(tbody.children).map(row => parseInt(row.dataset.index));
               order.splice(toIndex, 0, order.splice(fromIndex, 1)[0]);
               await fetch('/update_rule_order', {
                   method: 'POST',
                   headers: { 'Content-Type': 'application/json' },
                   body: JSON.stringify({ order })
               });
               await updateRules();
           });
           tbody.appendChild(row);
       });
       console.log('Updated rules');
   }

   async function moveRule(index, direction) {
       await fetch('/move_rule', {
           method: 'POST',
           headers: { 'Content-Type': 'application/json' },
           body: JSON.stringify({ index, direction })
       });
       await updateRules();
   }

   async function deleteRule(index) {
       await fetch('/delete_rule', {
           method: 'POST',
           headers: { 'Content-Type': 'application/json' },
           body: JSON.stringify({ index })
       });
       await updateRules();
   }

   async function submitRule() {
       const index = parseInt(document.getElementById('edit-rule-index').value);
       const rule = {
           src_ip: document.getElementById('src-ip').value,
           dst_ip: document.getElementById('dst-ip').value,
           proto: document.getElementById('proto').value,
           src_port: document.getElementById('src-port').value,
           dst_port: document.getElementById('dst-port').value,
           action: document.getElementById('action').value
       };
       const endpoint = index === -1 ? '/add_rule' : '/edit_rule';
       if (index !== -1) rule.index = index;
       const response = await fetch(endpoint, {
           method: 'POST',
           headers: { 'Content-Type': 'application/json' },
           body: JSON.stringify(rule)
       });
       const result = await response.json();
       if (result.status === 'success') {
           await updateRules();
           cancelEditRule();
       } else {
           alert(result.message);
       }
   }

   function cancelEditRule() {
       document.getElementById('rule-form').reset();
       document.getElementById('edit-rule-index').value = '-1';
   }

   function editRule(index) {
       fetchData('/rules').then(data => {
           const rule = data[index];
           document.getElementById('edit-rule-index').value = index;
           document.getElementById('src-ip').value = rule.src_ip || '';
           document.getElementById('dst-ip').value = rule.dst_ip || '';
           document.getElementById('proto').value = rule.proto || 'any';
           document.getElementById('src-port').value = rule.src_port || '';
           document.getElementById('dst-port').value = rule.dst_port || '';
           document.getElementById('action').value = rule.action;
       });
   }

   async function updateUsers() {
       const data = await fetchData('/users');
       const tbody = document.getElementById('users-body');
       tbody.innerHTML = '';
       data.forEach(user => {
           const row = document.createElement('tr');
           row.innerHTML = `
               <td>${user.username}</td>
               <td>${'*'.repeat(user.password.length)}</td>
               <td>
                   <button onclick="deleteUser('${user.username}')">Delete</button>
               </td>
           `;
           tbody.appendChild(row);
       });
       console.log('Updated users');
   }

   async function addUser() {
       const username = document.getElementById('new-username').value;
       const password = document.getElementById('new-password').value;
       await fetch('/add_user', {
           method: 'POST',
           headers: { 'Content-Type': 'application/json' },
           body: JSON.stringify({ username, password })
       });
       document.getElementById('add-user-form').reset();
       await updateUsers();
   }

   async function modifyUser() {
       const username = document.getElementById('modify-username').value;
       const new_password = document.getElementById('modify-password').value;
       await fetch('/modify_user', {
           method: 'POST',
           headers: { 'Content-Type': 'application/json' },
           body: JSON.stringify({ username, new_password })
       });
       document.getElementById('modify-user-form').reset();
       await updateUsers();
   }

   async function deleteUser(username) {
       await fetch('/delete_user', {
           method: 'POST',
           headers: { 'Content-Type': 'application/json' },
           body: JSON.stringify({ username })
       });
       await updateUsers();
   }

   async function updateAliases() {
       const data = await fetchData('/aliases');
       const tbody = document.getElementById('aliases-body');
       const datalist = document.getElementById('alias-list');
       tbody.innerHTML = '';
       datalist.innerHTML = '';
       data.forEach((alias, index) => {
           const row = document.createElement('tr');
           row.innerHTML = `
               <td>${alias.name}</td>
               <td>${alias.description}</td>
               <td>${alias.entries.join(', ')}</td>
               <td>
                   <button onclick="editAlias(${index})">Edit</button>
                   <button onclick="deleteAlias(${index})">Delete</button>
               </td>
           `;
           tbody.appendChild(row);
           const option = document.createElement('option');
           option.value = alias.name;
           datalist.appendChild(option);
       });
       console.log('Updated aliases');
   }

   async function submitAlias() {
       const index = parseInt(document.getElementById('edit-alias-index').value);
       const alias = {
           name: document.getElementById('alias-name').value,
           description: document.getElementById('alias-desc').value,
           entries: document.getElementById('alias-entries').value
       };
       const endpoint = index === -1 ? '/add_alias' : '/edit_alias';
       if (index !== -1) alias.index = index;
       await fetch(endpoint, {
           method: 'POST',
           headers: { 'Content-Type': 'application/json' },
           body: JSON.stringify(alias)
       });
       document.getElementById('alias-form').reset();
       document.getElementById('edit-alias-index').value = '-1';
       await updateAliases();
   }

   function cancelEditAlias() {
       document.getElementById('alias-form').reset();
       document.getElementById('edit-alias-index').value = '-1';
   }

   function editAlias(index) {
       fetchData('/aliases').then(data => {
           const alias = data[index];
           document.getElementById('edit-alias-index').value = index;
           document.getElementById('alias-name').value = alias.name;
           document.getElementById('alias-desc').value = alias.description;
           document.getElementById('alias-entries').value = alias.entries.join(', ');
       });
   }

   async function deleteAlias(index) {
       await fetch('/delete_alias', {
           method: 'POST',
           headers: { 'Content-Type': 'application/json' },
           body: JSON.stringify({ index })
       });
       await updateAliases();
   }

   async function uploadAliases() {
       const formData = new FormData(document.getElementById('upload-alias-form'));
       await fetch('/upload_aliases', {
           method: 'POST',
           body: formData
       });
       document.getElementById('upload-alias-form').reset();
       await updateAliases();
   }

   async function updateScanResults() {
       const data = await fetchData('/scan');
       const tbody = document.getElementById('scan-body');
       tbody.innerHTML = '';
       data.scan_results.forEach(result => {
           const row = document.createElement('tr');
           row.innerHTML = `
               <td>${result.host}</td>
               <td>${result.state}</td>
               <td>${result.ports.join(', ')}</td>
               <td>${data.anomalies[result.host] || 0}</td>
               <td>
                   <button onclick="addToBlacklist('${result.host}')">Block</button>
               </td>
           `;
           tbody.appendChild(row);
       });
       console.log('Updated scan results');
   }

   async function startScan() {
       const network = document.getElementById('scan-network').value;
       const ports = document.getElementById('scan-ports').value;
       document.getElementById('scan-loading').style.display = 'block';
       document.getElementById('start-scan-button').disabled = true;
       await fetch('/scan', {
           method: 'POST',
           headers: { 'Content-Type': 'application/json' },
           body: JSON.stringify({ network, port_range: ports })
       });
       await updateScanResults();
       document.getElementById('scan-loading').style.display = 'none';
       document.getElementById('start-scan-button').disabled = false;
   }

   function stopScan() {
       console.log('Scan stop not implemented');
   }

   async function updateBlacklist() {
       const data = await fetchData('/blacklist');
       const tbody = document.getElementById('blacklist-body');
       tbody.innerHTML = '';
       data.forEach(entry => {
           console.log(`Rendering blacklist entry: ${entry.ip}`);
           const row = document.createElement('tr');
           row.innerHTML = `
               <td>${entry.ip}</td>
               <td>${entry.reason || 'None'}</td>
               <td>${entry.added}</td>
               <td>${entry.temporary ? 'Yes' : 'No'}</td>
               <td>
                   <button onclick="editBlacklist('${entry.ip}')">Edit</button>
                   <button onclick="removeFromBlacklist('${entry.ip}')">Remove</button>
               </td>
           `;
           tbody.appendChild(row);
       });
       console.log(`Updated blacklist with ${data.length} entries`);
   }

   async function addToBlacklist(ip) {
       await fetch('/add_to_blacklist', {
           method: 'POST',
           headers: { 'Content-Type': 'application/json' },
           body: JSON.stringify({ ip })
       });
       await updateBlacklist();
   }

   async function removeFromBlacklist(ip) {
       await fetch('/remove_from_blacklist', {
           method: 'POST',
           headers: { 'Content-Type': 'application/json' },
           body: JSON.stringify({ ip })
       });
       await updateBlacklist();
   }

   async function saveBlacklistEdit() {
       const ip = document.getElementById('edit-blacklist-ip').value;
       const reason = document.getElementById('edit-blacklist-reason').value;
       await fetch('/edit_blacklist', {
           method: 'POST',
           headers: { 'Content-Type': 'application/json' },
           body: JSON.stringify({ ip, reason })
       });
       document.getElementById('edit-blacklist-form').style.display = 'none';
       await updateBlacklist();
   }

   function editBlacklist(ip) {
       console.log(`Editing blacklist entry for IP: ${ip}`);
       document.getElementById('edit-blacklist-ip').value = ip;
       document.getElementById('edit-blacklist-reason').value = '';
       document.getElementById('edit-blacklist-form').style.display = 'block';
   }

   async function saveIPSSettings() {
       const settings = {
           mode: document.getElementById('ips-mode').value,
           packet_threshold: document.getElementById('ips-threshold').value,
           auto_block: document.getElementById('ips-auto-block').checked,
           block_duration: document.getElementById('ips-block-duration').value
       };
       await fetch('/ips_settings', {
           method: 'POST',
           headers: { 'Content-Type': 'application/json' },
           body: JSON.stringify(settings)
       });
       console.log('Saved IPS settings');
   }

   function toggleAutoBlockOption() {
       const mode = document.getElementById('ips-mode').value;
       document.getElementById('ips-auto-block').disabled = mode !== 'IPS';
   }

   async function updateNATRules() {
       const data = await fetchData('/nat_rules');
       const tbody = document.getElementById('nat-body');
       tbody.innerHTML = '';
       data.forEach((rule, index) => {
           const row = document.createElement('tr');
           row.innerHTML = `
               <td>${rule.type}</td>
               <td>${rule.interface}</td>
               <td>${rule.proto || 'N/A'}</td>
               <td>${rule.orig_port || 'N/A'}</td>
               <td>${rule.dest_ip || 'N/A'}</td>
               <td>${rule.dest_port || 'N/A'}</td>
               <td>${rule.source_ip || 'N/A'}</td>
               <td>
                   <button onclick="deleteNATRule(${index})">Delete</button>
               </td>
           `;
           tbody.appendChild(row);
       });
       console.log('Updated NAT rules');
   }

   async function addNATRule() {
       const natType = document.getElementById('nat-type').value;
       const natRule = {
           type: natType,
           interface: document.getElementById('nat-interface').value
       };
       if (natType === 'PAT') {
           natRule.proto = document.getElementById('nat-proto').value;
           natRule.orig_port = document.getElementById('nat-orig-port').value;
           natRule.dest_ip = document.getElementById('nat-dest-ip').value;
           natRule.dest_port = document.getElementById('nat-dest-port').value;
       } else if (natType === 'SNAT') {
           natRule.source_ip = document.getElementById('nat-source-ip').value;
       }
       console.log(`Adding NAT rule:`, natRule);
       await fetch('/nat_rules', {
           method: 'POST',
           headers: { 'Content-Type': 'application/json' },
           body: JSON.stringify(natRule)
       });
       document.getElementById('nat-form').reset();
       await updateNATRules();
       toggleNATFields();
   }

   async function deleteNATRule(index) {
       await fetch('/delete_nat_rule', {
           method: 'POST',
           headers: { 'Content-Type': 'application/json' },
           body: JSON.stringify({ index })
       });
       await updateNATRules();
   }

   function toggleNATFields() {
       const natType = document.getElementById('nat-type').value;
       const protoField = document.getElementById('nat-proto');
       const origPortField = document.getElementById('nat-orig-port');
       const destIpField = document.getElementById('nat-dest-ip');
       const destPortField = document.getElementById('nat-dest-port');
       const sourceIpField = document.getElementById('nat-source-ip');
       console.log(`Toggling NAT fields for type: ${natType}`);
       protoField.style.display = natType === 'PAT' ? 'inline-block' : 'none';
       origPortField.style.display = natType === 'PAT' ? 'inline-block' : 'none';
       destIpField.style.display = natType === 'PAT' ? 'inline-block' : 'none';
       destPortField.style.display = natType === 'PAT' ? 'inline-block' : 'none';
       sourceIpField.style.display = natType === 'SNAT' ? 'inline-block' : 'none';
   }

   async function updateClients() {
       const data = await fetchData('/clients');
       const tbody = document.getElementById('clients-body');
       tbody.innerHTML = '';
       data.forEach(client => {
           const row = document.createElement('tr');
           row.innerHTML = `
               <td>${client.ip}</td>
               <td>${client.mac}</td>
               <td>${client.interface}</td>
               <td>${client.hostname}</td>
           `;
           tbody.appendChild(row);
       });
       console.log(`Updated clients with ${data.length} entries`);
   }

   document.getElementById('blacklist-ip')?.addEventListener('input', (e) => {
       console.log(`Typing in blacklist-ip: ${e.target.value}`);
   });

   document.getElementById('blacklist-ip')?.addEventListener('keypress', async (e) => {
       if (e.key === 'Enter') {
           console.log('Enter key pressed on blacklist-ip');
           const ip = e.target.value;
           const reason = document.getElementById('blacklist-reason').value;
           console.log(`Adding IP to blacklist: ${ip}`);
           await fetch('/add_to_blacklist', {
               method: 'POST',
               headers: { 'Content-Type': 'application/json' },
               body: JSON.stringify({ ip, reason })
           });
           document.getElementById('add-blacklist-form').reset();
           await updateBlacklist();
       }
   });

   document.getElementById('blacklist-add-button')?.addEventListener('click', async () => {
       const ip = document.getElementById('blacklist-ip').value;
       const reason = document.getElementById('blacklist-reason').value;
       console.log(`Adding IP to blacklist: ${ip}`);
       await fetch('/add_to_blacklist', {
           method: 'POST',
           headers: { 'Content-Type': 'application/json' },
           body: JSON.stringify({ ip, reason })
       });
       document.getElementById('add-blacklist-form').reset();
       await updateBlacklist();
   });

   document.addEventListener('DOMContentLoaded', async () => {
       await Promise.all([
           updateInterfaces(),
           updateSystemStats(),
           updateLogs(),
           updateRules(),
           updateUsers(),
           updateAliases(),
           updateScanResults(),
           updateBlacklist(),
           updateNotifications(),
           updateNATRules(),
           updateClients()
       ]);
       setInterval(updateInterfaces, 5000);
       setInterval(updateSystemStats, 5000);
       setInterval(updateLogs, 5000);
       setInterval(updateNotifications, 5000);
       setInterval(updateScanResults, 60000);
       setInterval(updateBlacklist, 5000);
       setInterval(updateClients, 30000);
       toggleNATFields();
   });
