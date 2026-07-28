require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const JavaScriptObfuscator = require('javascript-obfuscator');

const app = express();
const PORT = process.env.PORT || 3000;
const SALT = process.env.SALT || 'namco_default_salt_2026';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

// ========== 初始化数据库 ==========
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const NONCE_FILE = path.join(DATA_DIR, 'nonces.json');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '[]');
if (!fs.existsSync(NONCE_FILE)) fs.writeFileSync(NONCE_FILE, '{}');
const readUsers = () => JSON.parse(fs.readFileSync(USERS_FILE));
const writeUsers = (d) => fs.writeFileSync(USERS_FILE, JSON.stringify(d, null, 2));
const readNonces = () => JSON.parse(fs.readFileSync(NONCE_FILE));
const writeNonces = (d) => fs.writeFileSync(NONCE_FILE, JSON.stringify(d));

// ========== 工具函数 ==========
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const hmac256 = (k, s) => crypto.createHmac('sha256', k).update(s).digest('hex');
const aesEncrypt = (text, keyHex) => {
  const key = Buffer.from(keyHex.slice(0, 32), 'hex');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return iv.toString('base64') + '.' + ct.toString('base64') + '.' + tag.toString('base64');
};
const randomId = (n) => crypto.randomBytes(n).toString('hex');
const sessions = {}; // 管理员登录会话

// ========== 页面配置（原脚本硬编码参数移到这里） ==========
const PAGE_CONFIG = {
  matchUrls: [
    'https://parks2.bandainamco-am.co.jp/top_login.html',
    'https://parks2.bandainamco-am.co.jp/login.html*'
  ],
  emailSelectors: [
    { type: 'parentText', text: 'ご登録されたメールアドレス', maxDepth: 5 },
    { type: 'prevSiblingText', text: 'ご登録されたメールアドレス' }
  ],
  syncDelays: [100, 500],
  resizeDebounce: 150,
  styleProps: ['padding','border','borderRadius','fontFamily','fontSize','fontWeight','lineHeight','color','background'],
  lockEvents: ['input','change','blur']
};

// ========== 核心脚本模板（原脚本100%逻辑，后端动态渲染） ==========
function generateCoreScript(userEmail) {
  return `
(function(){
  'use strict';
  const LOCK_EMAIL = ${JSON.stringify(userEmail)};
  const CFG = ${JSON.stringify(PAGE_CONFIG)};
  let fakeEl=null, realEl=null, formEl=null, observer=null, rTimer=null, locking=false;
  
  function triggerEvents(el){['input','change','blur'].forEach(n=>el.dispatchEvent(new Event(n,{bubbles:true})));}
  function forceSet(){
    if(!realEl||locking||realEl.value===LOCK_EMAIL)return;
    locking=true; realEl.value=LOCK_EMAIL; triggerEvents(realEl); locking=false;
  }
  function syncSize(){
    if(!realEl||!fakeEl)return;
    const r=realEl.getBoundingClientRect(), pr=realEl.parentElement.getBoundingClientRect();
    Object.assign(fakeEl.style,{width:r.width+'px',height:r.height+'px',left:(r.left-pr.left)+'px',top:(r.top-pr.top)+'px'});
  }
  function findInput(){
    const all=document.querySelectorAll('input');
    for(const inp of all){
      let p=inp.parentElement;
      for(let i=0;i<5&&p;i++,p=p.parentElement)if(p.textContent.includes(CFG.emailSelectors[0].text))return inp;
      const pr=inp.previousElementSibling;
      if(pr&&pr.textContent.includes(CFG.emailSelectors[0].text))return inp;
    }
    return null;
  }
  function findForm(el){let e=el;while(e&&e.tagName!=='FORM')e=e.parentElement;return e;}
  
  function start(){
    realEl=findInput();
    if(!realEl||fakeEl)return;
    const wrap=realEl.parentElement;
    wrap.style.position='relative';
    forceSet();
    CFG.lockEvents.forEach(n=>realEl.addEventListener(n,forceSet));
    Object.assign(realEl.style,{opacity:'0.01',zIndex:'1',position:'relative'});
    formEl=findForm(realEl);
    if(formEl)formEl.addEventListener('submit',()=>realEl.value=LOCK_EMAIL,true);
    
    fakeEl=document.createElement('input');
    const st=getComputedStyle(realEl);
    fakeEl.style.cssText='position:absolute;z-index:10;box-sizing:border-box;margin:0;outline:none;'+
      CFG.styleProps.map(p=>p+':'+st.getPropertyValue(p)).join(';');
    fakeEl.autocomplete='off';
    fakeEl.placeholder=realEl.placeholder||'';
    fakeEl.addEventListener('keydown',e=>{if(e.key==='Enter'&&formEl){e.preventDefault();formEl.submit();}});
    wrap.appendChild(fakeEl);
    
    syncSize();
    CFG.syncDelays.forEach(d=>setTimeout(syncSize,d));
    window.addEventListener('resize',()=>{clearTimeout(rTimer);rTimer=setTimeout(syncSize,CFG.resizeDebounce);});
    window.addEventListener('orientationchange',()=>{clearTimeout(rTimer);rTimer=setTimeout(syncSize,CFG.resizeDebounce);});
  }
  
  observer=new MutationObserver(()=>{if(findInput()&&!fakeEl)start();});
  observer.observe(document.documentElement,{childList:true,subtree:true});
  if(document.readyState==='loading')window.addEventListener('DOMContentLoaded',start);
  else start();
  setTimeout(start,1000);
})();`;
}

// ========== 混淆 + 加密 ==========
async function obfuscateAndEncrypt(jsCode, appSecret, ts) {
  // 1. 混淆
  const obResult = JavaScriptObfuscator.obfuscate(jsCode, {
    compact: true,
    controlFlowFlattening: true,
    controlFlowFlatteningThreshold: 0.8,
    stringArray: true,
    stringArrayEncoding: ['rc4'],
    stringArrayThreshold: 1,
    deadCodeInjection: true,
    deadCodeInjectionThreshold: 0.3,
    identifierNamesGenerator: 'hexadecimal',
    renameGlobals: true,
    selfDefending: true,
    disableConsoleOutput: false
  });
  const obCode = obResult.getObfuscatedCode();
  
  // 2. 加过期时间（10分钟）
  const expireAt = Date.now() + 10 * 60 * 1000;
  const finalCode = expireAt.toString().padStart(13,'0') + obCode;
  
  // 3. AES加密
  const keyId = randomId(8);
  const derivedKey = hmac256(appSecret + SALT, keyId + ts);
  const encrypted = aesEncrypt(finalCode, derivedKey);
  
  return { keyId, encryptedScript: encrypted };
}

// ========== 中间件 ==========
app.use(express.json({ limit: '1mb' }));
app.use(express.static('public'));

// 权限校验中间件
function verifyAuth(req, res, next) {
  try {
    const { appKey, timestamp, nonce, sign, deviceFingerprint, lockEmail } = req.body;
    if (!appKey || !timestamp || !nonce || !sign || !deviceFingerprint) return res.json({ code: 400, msg: '参数缺失' });
    
    // 时间戳校验 ±30秒
    if (Math.abs(Date.now() - parseInt(timestamp)) > 30000) return res.json({ code: 401, msg: '请求过期' });
    
    // Nonce 防重放
    const nonces = readNonces();
    if (nonces[nonce]) return res.json({ code: 401, msg: '非法请求' });
    nonces[nonce] = Date.now();
    Object.keys(nonces).forEach(k => { if (Date.now() - nonces[k] > 60000) delete nonces[k]; });
    writeNonces(nonces);
    
    // 查用户
    const users = readUsers();
    const user = users.find(u => u.appKey === appKey && u.active);
    if (!user) return res.json({ code: 403, msg: '密钥无效' });
    
    // 校验签名
    const signMsg = [appKey, timestamp, nonce, deviceFingerprint, lockEmail].join('|');
    const expectSign = hmac256(user.appSecretHash + SALT, signMsg);
    if (sign !== expectSign) return res.json({ code: 403, msg: '签名错误' });
    
    // 设备绑定校验（可选，注释掉就是不绑定）
    // if (user.deviceFp && user.deviceFp !== deviceFingerprint) return res.json({ code: 403, msg: '设备不匹配' });
    
    req.user = user;
    next();
  } catch (e) {
    res.json({ code: 500, msg: '服务器错误' });
  }
}

// ========== 接口 ==========
// 获取核心脚本（油猴调用）
app.post('/api/v1/get', verifyAuth, async (req, res) => {
  try {
    const { lockEmail, timestamp } = req.body;
    const core = generateCoreScript(lockEmail);
    const result = await obfuscateAndEncrypt(core, req.user.appSecretHash, timestamp);
    // 更新调用记录
    const users = readUsers();
    const idx = users.findIndex(u => u.appKey === req.user.appKey);
    if (idx >= 0) {
      users[idx].lastUsed = new Date().toISOString();
      users[idx].callCount = (users[idx].callCount || 0) + 1;
      writeUsers(users);
    }
    res.json({ code: 0, ...result });
  } catch (e) {
    res.json({ code: 500, msg: '生成失败' });
  }
});

// 管理员登录
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (password === ADMIN_PASSWORD) {
    const sid = randomId(16);
    sessions[sid] = Date.now() + 24 * 3600 * 1000;
    res.json({ code: 0, sid });
  } else {
    res.json({ code: 401, msg: '密码错误' });
  }
});

// 管理员中间件
function adminAuth(req, res, next) {
  const sid = req.headers['x-admin-sid'];
  if (sid && sessions[sid] && sessions[sid] > Date.now()) next();
  else res.json({ code: 401, msg: '请先登录' });
}

// 获取用户列表
app.get('/api/admin/users', adminAuth, (req, res) => {
  const users = readUsers().map(u => ({
    ...u,
    appSecretHash: undefined, // 绝不返回密钥哈希
    appSecret: undefined
  }));
  res.json({ code: 0, data: users });
});

// 新增用户（返回仅一次的AppSecret）
app.post('/api/admin/users', adminAuth, (req, res) => {
  const { remark } = req.body;
  const appKey = randomId(8);
  const appSecret = randomId(16); // 仅这次返回明文
  const appSecretHash = sha256(appSecret);
  const users = readUsers();
  users.push({
    appKey, appSecretHash, remark: remark || '未命名用户',
    active: true, createdAt: new Date().toISOString(),
    lastUsed: null, callCount: 0, deviceFp: null
  });
  writeUsers(users);
  res.json({ code: 0, data: { appKey, appSecret, remark } });
});

// 切换启用/吊销
app.post('/api/admin/users/:key/toggle', adminAuth, (req, res) => {
  const users = readUsers();
  const u = users.find(x => x.appKey === req.params.key);
  if (!u) return res.json({ code: 404 });
  u.active = !u.active;
  writeUsers(users);
  res.json({ code: 0 });
});

// 删除用户
app.delete('/api/admin/users/:key', adminAuth, (req, res) => {
  let users = readUsers();
  users = users.filter(x => x.appKey !== req.params.key);
  writeUsers(users);
  res.json({ code: 0 });
});

// 健康检查
app.get('/health', (req, res) => res.send('OK'));

app.listen(PORT, () => console.log('服务运行在端口 ' + PORT));
