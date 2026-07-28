// ==UserScript==
// @name         NamcoParks 邮箱固定【后端加密版】
// @namespace    http://tampermonkey.net/
// @version      1.0
// @description  核心逻辑后端加密下发，前端仅设置邮箱密钥
// @author       You
// @match        https://parks2.bandainamco-am.co.jp/*
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_registerMenuCommand
// @grant        GM_xmlhttpRequest
// @connect      your-app-name.onrender.com  // ⚠️ 装好后改成你自己的Render域名！
// ==/UserScript==

(function(){
  'use strict';
  // ========== 👇 装好后必须修改这里！ ==========
  const API_BASE = 'https://your-app-name.onrender.com'; // 改成你的 https://xxx.onrender.com
  const SALT = 'namco_default_salt_2026'; // 和后端 .env 里的 SALT 一致
  // ==========================================

  async function sha256(s){const b=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s));return Array.from(new Uint8Array(b)).map(x=>x.toString(16).padStart(2,'0')).join('')}
  async function hmac(k,s){const kb=await crypto.subtle.importKey('raw',new TextEncoder().encode(k),{name:'HMAC',hash:'SHA-256'},false,['sign']);const sig=await crypto.subtle.sign('HMAC',kb,new TextEncoder().encode(s));return Array.from(new Uint8Array(sig)).map(x=>x.toString(16).padStart(2,'0')).join('')}
  async function aesDecrypt(enc,keyHex){
    const[ivB64,ctB64,tagB64]=enc.split('.');
    const key=await crypto.subtle.importKey('raw',Uint8Array.from(atob(keyHex.slice(0,44)),c=>c.charCodeAt(0)),{name:'AES-GCM'},false,['decrypt']);
    const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:Uint8Array.from(atob(ivB64),c=>c.charCodeAt(0)),tagLength:128},key,Uint8Array.from(atob(ctB64+tagB64),c=>c.charCodeAt(0)));
    return new TextDecoder().decode(pt);
  }
  function getFP(){return sha256([navigator.userAgent,screen.width+'x'+screen.height,Intl.DateTimeFormat().resolvedOptions().timeZone,navigator.language].join('|'))}

  // 油猴菜单
  GM_registerMenuCommand('📧 设置固定邮箱',()=>{
    const e=prompt('输入要固定的邮箱：',GM_getValue('email')||'');
    if(e&&/@/.test(e)){GM_setValue('email',e);alert('已保存，刷新生效')}
  });
  GM_registerMenuCommand('🔑 设置密钥',()=>{
    const k=prompt('输入 AppKey：',GM_getValue('ak')||'');
    const s=prompt('输入 AppSecret：','');
    if(k&&s){GM_setValue('ak',k);GM_setValue('as',s);alert('已保存')}
  });
  GM_registerMenuCommand('ℹ️ 查看当前配置',()=>{
    alert('邮箱：'+(GM_getValue('email')||'未设置')+'\nAppKey：'+(GM_getValue('ak')||'未设置'));
  });

  // 主流程
  async function run(){
    const ak=GM_getValue('ak'),as=GM_getValue('as'),em=GM_getValue('email');
    if(!ak||!as||!em){console.log('⚠️ 请先点油猴图标→本脚本→设置邮箱和密钥');return}
    const ts=Date.now().toString();
    const nonce=Array.from(crypto.getRandomValues(new Uint8Array(8))).map(x=>x.toString(16).padStart(2,'0')).join('');
    const fp=await getFP();
    const sign=await hmac(as+SALT,[ak,ts,nonce,fp,em].join('|'));
    
    GM_xmlhttpRequest({
      method:'POST',url:API_BASE+'/api/v1/get',
      headers:{'Content-Type':'application/json'},
      data:JSON.stringify({appKey:ak,timestamp:ts,nonce,sign,deviceFingerprint:fp,lockEmail:em,pageUrl:location.href}),
      responseType:'json',
      onload:async res=>{
        try{
          const d=JSON.parse(res.responseText);
          if(d.code!==0)throw new Error(d.msg||'失败');
          const dk=await hmac(as+SALT,d.keyId+ts);
          const code=await aesDecrypt(d.encryptedScript,dk);
          const exp=parseInt(code.slice(0,13),10);
          if(Date.now()>exp)throw new Error('过期');
          const s=document.createElement('script');
          s.textContent='(function(){'+code.slice(13)+'})();';
          document.documentElement.appendChild(s);s.remove();
        }catch(e){console.error('❌',e.message)}
      }
    });
  }
  if(document.readyState==='loading')window.addEventListener('DOMContentLoaded',run);else run();
})();
