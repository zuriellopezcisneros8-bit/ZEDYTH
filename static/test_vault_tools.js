// Pruebas de static/js/vault_tools.js. Ejecutar: node test_vault_tools.js
const assert = require('assert');
const T = require('./static/js/vault_tools.js');
let n = 0; const ok = (nombre, f) => { try { const r = f(); if (r && r.then) return r.then(() => { n++; console.log('ok  ', nombre); }); n++; console.log('ok  ', nombre); } catch (e) { console.error('FALLA', nombre, '\n', e.message); process.exitCode = 1; } };

(async () => {
ok('base64 ida y vuelta con acentos', () => { assert.strictEqual(T.b64Dec(T.b64Enc('Auditoría ñ €')), 'Auditoría ñ €'); assert.strictEqual(T.b64Enc('hola'), 'aG9sYQ=='); });
ok('base64url sin relleno', () => assert.strictEqual(T.b64Dec('aG9sYQ'), 'hola'));
ok('hex', () => { assert.strictEqual(T.hexEnc('Az'), '417a'); assert.strictEqual(T.hexDec('41 7a'), 'Az'); assert.throws(() => T.hexDec('zz')); });
ok('url', () => { assert.strictEqual(T.urlEnc("a b&c='"), 'a%20b%26c%3D%27'); assert.strictEqual(T.urlDec('a%20b+c'), 'a b c'); });
ok('md5 vectores conocidos', () => { assert.strictEqual(T.md5(''), 'd41d8cd98f00b204e9800998ecf8427e'); assert.strictEqual(T.md5('abc'), '900150983cd24fb0d6963f7d28e17f72'); assert.strictEqual(T.md5('The quick brown fox jumps over the lazy dog'), '9e107d9d372bb6826bd81d3542a419d6'); assert.strictEqual(T.md5('a'.repeat(100)), require('crypto').createHash('md5').update('a'.repeat(100)).digest('hex')); assert.strictEqual(T.md5('ñandú €'), require('crypto').createHash('md5').update('ñandú €').digest('hex')); });
await ok('sha256 y sha1', async () => { assert.strictEqual(await T.sha('SHA-256', 'abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'); assert.strictEqual(await T.sha('SHA-1', 'abc'), 'a9993e364706816aba3e25717850c26c9cd0d89d'); });
ok('jwt', () => { const h = Buffer.from('{"alg":"HS256","typ":"JWT"}').toString('base64url'), p = Buffer.from('{"sub":"1","exp":1}').toString('base64url'); const r = T.jwtDecode('Bearer ' + h + '.' + p + '.firma'); assert.strictEqual(r.encabezado.alg, 'HS256'); assert.ok(r.avisos[0].startsWith('Caducado')); assert.throws(() => T.jwtDecode('abc')); const sn = T.jwtDecode(Buffer.from('{"alg":"none"}').toString('base64url') + '.' + p + '.'); assert.ok(sn.avisos.some(a => a.includes('none'))); });
ok('defang pedido por el usuario', () => { assert.strictEqual(T.defang('http://192.168.1.1'), 'hxxp://192[.]168[.]1[.]1'); assert.strictEqual(T.defang('https://evil.com/a.php'), 'hxxps://evil[.]com/a[.]php'); assert.strictEqual(T.defang('a@b.com'), 'a[@]b[.]com'); });
ok('fang revierte defang', () => { for (const s of ['http://192.168.1.1', 'https://evil.com/a.php?x=1', 'soc@evil.com']) assert.strictEqual(T.fang(T.defang(s)), s); });
ok('iocs', () => {
  const r = T.extraerIoCs('C2 en hxxp://evil[.]example[.]com/a.php y 10.0.0.5, también 999.1.1.1 y 8.8.8.8.\nmd5 d41d8cd98f00b204e9800998ecf8427e sha256 ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\nsoc@Empresa.com.mx usó C:\\Windows\\Temp\\x.exe y /etc/passwd, ver CVE-2024-12345. archivo script.py no es dominio');
  assert.deepStrictEqual(r.ips, ['10.0.0.5', '8.8.8.8']); assert.strictEqual(r.md5.length, 1); assert.strictEqual(r.sha256.length, 1); assert.strictEqual(r.sha1.length, 0);
  assert.ok(r.urls[0].startsWith('http://evil.example.com/a.php')); assert.ok(r.dominios.includes('evil.example.com')); assert.ok(r.dominios.includes('empresa.com.mx')); assert.ok(!r.dominios.some(d => d.endsWith('.py')));
  assert.deepStrictEqual(r.correos, ['soc@empresa.com.mx']); assert.ok(r.rutas.includes('C:\\Windows\\Temp\\x.exe') && r.rutas.includes('/etc/passwd')); assert.deepStrictEqual(r.cves, ['CVE-2024-12345']);
  assert.strictEqual(T.totalIoCs(T.extraerIoCs('')), 0);
});
ok('hash de 64 no se cuenta también como md5/sha1', () => { const r = T.extraerIoCs('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'); assert.deepStrictEqual([r.md5.length, r.sha1.length, r.sha256.length], [0, 0, 1]); });
ok('detección de lenguaje', () => {
  const c = { 'nmap -sC -sV -p- {{TARGET_IP}} -oN {{OUTPUT_FILE}}': 'terminal', '#!/bin/bash\necho hola': 'bash', 'import os\ndef f(x):\n  return x': 'python', 'Get-ChildItem | Where-Object { $_.Length -gt 1 }': 'powershell', "SELECT * FROM users WHERE id=1": 'sql', '#include <stdio.h>\nint main(){}': 'cpp', 'rule Demo {\n strings:\n $a = "x"\n condition:\n $a\n}': 'yara', '^\\d{3}-\\w+$': 'regex', 'const a = () => 1': 'javascript', 'hola mundo': 'texto' };
  for (const [k, v] of Object.entries(c)) assert.strictEqual(T.detectarLenguaje(k), v, k);
});
ok('resaltado escapa HTML y marca partes', () => { const h = T.resaltar('echo "<b>" # nota {{IP}} -sV 22', 'bash'); assert.ok(!h.includes('<b>')); assert.ok(h.includes('vt-s') && h.includes('vt-c') && h.includes('vt-ph') && h.includes('vt-f')); assert.ok(T.resaltar('nmap -sV {{TARGET_IP}} 22', 'terminal').includes('<span class="vt-ph">{{TARGET_IP}}</span>')); assert.ok(T.resaltar('x = "<script>"', 'python').includes('&lt;script&gt;')); assert.strictEqual(T.resaltar('', 'bash'), ''); });
ok('resaltado conserva el texto exacto', () => { const src = 'for i in 1 2; do echo "$i" # fin\ndone {{X}}'; const txt = T.resaltar(src, 'bash').replace(/<[^>]+>/g, '').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&amp;/g, '&').replace(/&#39;/g, "'"); assert.strictEqual(txt, src); });
ok('placeholders', () => { assert.deepStrictEqual(T.placeholders('nmap {{TARGET_IP}} -oN {{OUTPUT_FILE}} {{TARGET_IP}}'), ['TARGET_IP', 'OUTPUT_FILE']); assert.strictEqual(T.rellenar('nmap {{TARGET_IP}} -oN {{OUTPUT_FILE}}', { TARGET_IP: '10.0.0.1' }), 'nmap 10.0.0.1 -oN {{OUTPUT_FILE}}'); });
ok('password', () => { const r = T.generarPassword(24, {}); assert.strictEqual(r.valor.length, 24); assert.ok(/[a-z]/.test(r.valor) && /[A-Z]/.test(r.valor) && /\d/.test(r.valor) && /[^A-Za-z0-9]/.test(r.valor)); assert.ok(r.entropia > 120); assert.throws(() => T.generarPassword(10, { minusculas: false, mayusculas: false, numeros: false, simbolos: false })); assert.ok(/^\d+$/.test(T.generarPassword(12, { minusculas: false, mayusculas: false, simbolos: false }).valor)); });
ok('uuid', () => assert.ok(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(T.uuid4())));
ok('markdown seguro y wiki-links', () => {
  const h = T.renderMarkdown('# Título <img src=x onerror=1>\n\n- **uno** [[Auditoría API]]\n- [[No existe]]\n\n```bash\necho "<x>"\n```\n\n[ok](https://a.com) [mal](javascript:alert(1))', t => t === 'Auditoría API' ? { tipo: 'nota', id: 7 } : null);
  assert.ok(!/<img/.test(h)); assert.ok(h.includes('data-id="7"') && h.includes('vt-wiki-roto')); assert.ok(h.includes('<h2>') && h.includes('<strong>uno</strong>')); assert.ok(h.includes('rel="noopener noreferrer"')); assert.ok(!h.includes('href="javascript:')); assert.ok(h.includes('&lt;x&gt;'));
});
ok('markdown: tabla y casillas', () => { const h = T.renderMarkdown('| a | b |\n|---|---|\n| 1 | 2 |\n\n- [ ] x\n- [x] y'); assert.ok(h.includes('<th>a</th>') && h.includes('<td>2</td>') && h.includes('☐ x') && h.includes('☑ y')); });
console.log('\n' + n + ' pruebas OK');
})();
